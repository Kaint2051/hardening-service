// Agent tự phát triển — Reporter (mục 4.3 architecture-proposal.md).
//
// Reporter chạy 6 vòng lặp độc lập song song sau khi enroll xong: heartbeat
// (main.go), scan OpenSCAP cục bộ (scan.go), FIM hash định kỳ (fim.go), renew
// cert mTLS (main.go), poll/thực thi remediation job qua Executor — tính
// năng Active Response (remediate.go), và báo số liệu tài nguyên CPU/RAM/
// Disk/Network mỗi ~3 phút (metrics.go). Executor (quyền cao hơn, nhận
// job qua Unix socket) là 1 BINARY RIÊNG (./executor/), không lẫn vào tiến
// trình Reporter (quyền tối thiểu) đang chạy đây.
//
// Bootstrap PKI (con gà-quả trứng kinh điển của mọi enrollment): agent CHƯA
// có cert nên KHÔNG thể tự verify server cert của Agent Manager bằng chính
// cert đó. Giải pháp ở đây là KHÔNG dùng InsecureSkipVerify — operator phải
// tự đặt sẵn ca-root.crt (KHÔNG bí mật, chỉ root KEY mới bí mật) lên máy
// đích CÙNG lúc với bootstrap token (cùng kênh out-of-band, vd scp), agent
// verify server bằng root đó ngay từ request /enroll đầu tiên.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	managerURL     string
	managerTLSName string
	hostname       string
	stateDir       string
	heartbeatEvery time.Duration
	osReleasePath  string
	// osFamily/osVersion: đọc 1 LẦN lúc khởi động (main(), qua detectOS) —
	// OS không đổi trong đời process, không cần đọc lại mỗi lần heartbeat.
	// Rỗng nghĩa là không tự nhận diện được (file thiếu/hỏng) — heartbeat()
	// bỏ qua field này thay vì gửi chuỗi rỗng (xem app/schemas.py:
	// AgentHeartbeatRequest — rỗng/thiếu KHÔNG được coi là "xoá" giá trị đã
	// biết ở Orchestrator).
	osFamily  string
	osVersion string
	scanInterval   time.Duration
	scanTimeout    time.Duration
	scapProfile    string
	scapDatastream string
	fimInterval    time.Duration
	fimPaths       []string
	// Cadence báo metrics tài nguyên (CPU/RAM/Disk/Network) — TÁCH RIÊNG
	// khỏi heartbeatEvery vì collectMetrics() cần ~1s sleep để lấy delta
	// CPU/network, không muốn làm heartbeat (tín hiệu "còn sống") bị trễ
	// theo, xem metrics.go.
	metricsInterval time.Duration

	// Active Response (Reporter <-> Agent Manager <-> Orchestrator <->
	// Executor) — xem remediate.go. Kill-switch thật (bật/tắt tính năng) nằm
	// ở Orchestrator (settings.active_response_enabled), KHÔNG phải ở đây:
	// Reporter luôn poll, Orchestrator tự quyết định có job để trả hay không.
	remediatePollInterval time.Duration
	contentCacheDir       string
	executorSocketPath    string
}

func loadConfig() config {
	hostname := getenv("AGENT_HOSTNAME", "")
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			log.Fatalf("thiếu AGENT_HOSTNAME và không tự lấy được hostname hệ thống: %v", err)
		}
		hostname = h
	}
	return config{
		managerURL:     getenv("AGENT_MANAGER_URL", "https://localhost:8443"),
		managerTLSName: getenv("AGENT_MANAGER_TLS_SERVERNAME", "agent-manager"),
		hostname:       hostname,
		stateDir:       getenv("AGENT_STATE_DIR", "/etc/hardening-agent"),
		heartbeatEvery: getenvDuration("AGENT_HEARTBEAT_INTERVAL", 60*time.Second),
		osReleasePath:  getenv("AGENT_OS_RELEASE_PATH", "/etc/os-release"),
		// Mặc định khớp entry "ubuntu2204-cis-level1-server" trong
		// apps/orchestrator/app/jobs.py:SCAP_PROFILES — cùng 1 profile dù
		// scan tới từ đường agentless (SSH) hay agent-based (Reporter).
		scanInterval: getenvDuration("AGENT_SCAN_INTERVAL", time.Hour),
		// oscap-ssh phía agentless dùng timeout 300s (job-dispatcher) cho cả
		// vòng SSH+scan; scan cục bộ (không có overhead SSH) hiếm khi cần lâu
		// hơn, nhưng benchmark CIS đầy đủ trên máy chậm vẫn có thể mất vài
		// phút — 10 phút đủ dư mà vẫn chặn được treo vô hạn.
		scanTimeout:    getenvDuration("AGENT_SCAN_TIMEOUT", 10*time.Minute),
		scapProfile:    getenv("AGENT_SCAP_PROFILE", "xccdf_org.ssgproject.content_profile_cis_level1_server"),
		scapDatastream: getenv("AGENT_SCAP_DATASTREAM", "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"),
		fimInterval:    getenvDuration("AGENT_FIM_INTERVAL", 5*time.Minute),
		fimPaths:       getenvList("AGENT_FIM_PATHS", []string{"/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow"}),
		metricsInterval: getenvDuration("AGENT_METRICS_INTERVAL", 3*time.Minute),

		remediatePollInterval: getenvDuration("AGENT_REMEDIATE_POLL_INTERVAL", 15*time.Second),
		// Mặc định PHẢI trùng path vật lý với EXECUTOR_SIGNED_CONTENT_DIR mặc
		// định phía Executor (apps/agent/executor/main.go) — Reporter ghi
		// bundle vào đây, Executor đọc lại CÙNG đường dẫn qua socket, không
		// qua mạng lần 2.
		contentCacheDir: getenv("AGENT_CONTENT_CACHE_DIR", "/var/cache/hardening-agent/content"),
		// Khớp EXECUTOR_SOCKET_PATH mặc định phía Executor.
		executorSocketPath: getenv("AGENT_EXECUTOR_SOCKET_PATH", "/run/hardening-agent/executor.sock"),
	}
}

func (c config) certPath() string  { return filepath.Join(c.stateDir, "agent.crt") }
func (c config) keyPath() string   { return filepath.Join(c.stateDir, "agent.key") }
func (c config) rootPath() string  { return filepath.Join(c.stateDir, "ca-root.crt") }
func (c config) tokenPath() string { return filepath.Join(c.stateDir, "enroll-token") }

func main() {
	cfg := loadConfig()

	cfg.osFamily, cfg.osVersion = detectOS(cfg.osReleasePath)
	if cfg.osFamily == "" {
		log.Printf("không tự nhận diện được OS từ %s — heartbeat sẽ không báo os_family/os_version (điền tay qua PATCH /hosts/{hostname} nếu cần remediate)", cfg.osReleasePath)
	} else {
		log.Printf("tự nhận diện OS: %s %s", cfg.osFamily, cfg.osVersion)
	}

	hadCertsBeforeStartup := fileExists(cfg.certPath()) && fileExists(cfg.keyPath())
	if !hadCertsBeforeStartup {
		log.Printf("chưa enroll — đọc bootstrap token tại %s", cfg.tokenPath())
		if err := enroll(cfg); err != nil {
			log.Fatalf("enroll thất bại: %v", err)
		}
		log.Printf("enroll thành công, cert lưu tại %s", cfg.certPath())
	}

	client, certs, err := buildMTLSClient(cfg.certPath(), cfg.keyPath(), cfg.rootPath(), cfg.managerTLSName)
	if err != nil {
		if hadCertsBeforeStartup {
			// cert.crt/agent.key đã tồn tại TRƯỚC khi process này chạy nhưng
			// không nạp được cùng nhau (lệch cặp, hỏng PEM...) — writeFileAtomic
			// (enroll/renewCert) khép kín từng file riêng lẻ nhưng KHÔNG đảm
			// bảo cert+key được thay CÙNG lúc như 1 giao dịch: crash đúng lúc
			// giữa 2 lần rename (renew định kỳ, hoặc enroll ban đầu) có thể để
			// lại 1 cặp lệch nhau — gap hẹp đã biết, chấp nhận ở mức hiện tại
			// thay vì đổi sang layout combined-file/symlink-swap phức tạp hơn
			// (xem review "atomicity" trong lịch sử dự án). Bootstrap token đã
			// bị xoá sau lần enroll gốc nên KHÔNG có đường tự phục hồi — báo rõ
			// ràng thay vì để log lỗi TLS chung chung khó hiểu.
			log.Fatalf(
				"cert/key tại %s/%s đã tồn tại nhưng không nạp được (có thể lệch cặp do crash giữa lúc ghi) — "+
					"XOÁ %s VÀ %s RỒI TẠO ENROLLMENT TOKEN MỚI (POST /hosts/{hostname}/agent-enrollment-tokens) để re-enroll thủ công: %v",
				cfg.certPath(), cfg.keyPath(), cfg.certPath(), cfg.keyPath(), err,
			)
		}
		log.Fatalf("không dựng được mTLS client ngay sau enroll (không nên xảy ra — báo lỗi này cho dev): %v", err)
	}

	// 6 vòng lặp độc lập, mỗi cái tự quản lý lịch riêng (khoảng cách khác
	// nhau: heartbeat vài chục giây, scan hàng giờ, FIM vài phút, renew cert
	// ở nửa chu kỳ hiệu lực cert — thường vài giờ, poll remediation job vài
	// chục giây — xem remediate.go, báo metrics tài nguyên vài phút — xem
	// metrics.go) — không có phụ thuộc lẫn nhau, 1 vòng lỗi/chậm không chặn
	// các vòng còn lại.
	go runHeartbeatLoop(client, cfg)
	go runScanLoop(client, cfg)
	go runFimLoop(client, cfg)
	go runRenewalLoop(client, certs, cfg)
	go runRemediateLoop(client, cfg)
	go runMetricsLoop(client, cfg)
	select {}
}

// runProtected chạy fn() với recover() bọc ngoài. 5 vòng lặp của Reporter
// (heartbeat/scan/fim/renewal/remediate — xem main() ở trên) chạy trong 5
// goroutine riêng của CÙNG 1 process; comment lúc khởi động các goroutine
// này tuyên bố "1 vòng lỗi/chậm không chặn các vòng còn lại", nhưng Go KHÔNG
// tự đảm bảo điều đó cho panic — 1 panic không recover ở BẤT KỲ goroutine
// nào sẽ crash TOÀN BỘ tiến trình (kể cả 4 vòng lặp khác đang chạy tốt),
// khiến 1 job remediate đang thực thi dở (nếu panic ở goroutine khác) bị bỏ
// rơi giữa đường không ai báo cáo (phát hiện qua rà soát đối kháng). Chỉ log
// rồi để vòng lặp NGOÀI tự thử lại ở lần lặp kế tiếp — không resume ngay
// trong defer (tránh panic-loop tốc độ cao nếu lỗi lặp lại mỗi lần).
func runProtected(loopName string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("vòng lặp %s panic (đã recover, KHÔNG dừng vòng lặp/tiến trình): %v", loopName, r)
		}
	}()
	fn()
}

func runHeartbeatLoop(client *http.Client, cfg config) {
	log.Printf("bắt đầu vòng lặp heartbeat mỗi %s tới %s", cfg.heartbeatEvery, cfg.managerURL)
	for {
		runProtected("heartbeat", func() {
			if err := heartbeat(client, cfg.managerURL, cfg.hostname, cfg.osFamily, cfg.osVersion); err != nil {
				log.Printf("heartbeat lỗi: %v", err)
			} else {
				log.Printf("heartbeat OK")
			}
		})
		time.Sleep(cfg.heartbeatEvery)
	}
}

func enroll(cfg config) error {
	tokenBytes, err := os.ReadFile(cfg.tokenPath())
	if err != nil {
		return fmt.Errorf("đọc bootstrap token thất bại (operator phải đặt file tại %s trước): %w", cfg.tokenPath(), err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	httpClient, err := buildEnrollClient(cfg.rootPath(), cfg.managerTLSName)
	if err != nil {
		return err
	}

	reqBody, err := json.Marshal(map[string]string{"hostname": cfg.hostname, "token": token})
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(cfg.managerURL+"/enroll", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("gọi Agent Manager thất bại: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("đọc phản hồi enroll thất bại: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent Manager từ chối enroll (%d): %s", resp.StatusCode, string(respBody))
	}

	var cr struct {
		CertPEM   string `json:"cert_pem"`
		KeyPEM    string `json:"key_pem"`
		CARootPEM string `json:"ca_root_pem"`
	}
	if err := json.Unmarshal(respBody, &cr); err != nil {
		return fmt.Errorf("phản hồi enroll không hợp lệ: %w", err)
	}

	if err := os.MkdirAll(cfg.stateDir, 0700); err != nil {
		return fmt.Errorf("tạo thư mục state %s thất bại: %w", cfg.stateDir, err)
	}
	// writeFileAtomic (không phải os.WriteFile trần) — cùng lý do renewCert
	// dùng nó: tránh 1 file cert/key nửa-vời nếu process bị giết giữa chừng
	// ghi. Đây là lần ghi cert/key ĐẦU TIÊN của agent nên rủi ro thực tế thấp
	// hơn renew (chạy 1 lần lúc bootstrap, không định kỳ), nhưng không có lý
	// do để nó kém an toàn hơn renewCert.
	if err := writeFileAtomic(cfg.certPath(), []byte(cr.CertPEM), 0600); err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.keyPath(), []byte(cr.KeyPEM), 0600); err != nil {
		return err
	}
	// ca_root_pem trong response thường TRÙNG với ca-root.crt operator đã đặt
	// sẵn (cùng 1 root CA) — vẫn ghi đè để agent giữ đúng bản Orchestrator
	// đang thực sự dùng, phòng trường hợp operator đặt nhầm bản cũ.
	if err := writeFileAtomic(cfg.rootPath(), []byte(cr.CARootPEM), 0600); err != nil {
		return err
	}
	if err := os.Remove(cfg.tokenPath()); err != nil {
		log.Printf("cảnh báo: không xoá được token file %s sau khi dùng (tự xoá thủ công): %v", cfg.tokenPath(), err)
	}
	return nil
}

func heartbeat(client *http.Client, managerURL, hostname, osFamily, osVersion string) error {
	payload := map[string]string{"hostname": hostname}
	// Bỏ hẳn key thay vì gửi chuỗi rỗng — Orchestrator coi field THIẾU khác
	// field rỗng: thiếu = "Agent không báo gì cả" (giữ nguyên giá trị cũ),
	// còn field có mặt nhưng rỗng lẽ ra không nên xảy ra (Agent Manager relay
	// nguyên map này, không tự bơm "" vào) nhưng vẫn tránh để chắc.
	if osFamily != "" {
		payload["os_family"] = osFamily
	}
	if osVersion != "" {
		payload["os_version"] = osVersion
	}
	return postAndExpect(client, managerURL+"/heartbeat", payload, http.StatusNoContent)
}

// detectOS đọc /etc/os-release (chuẩn systemd, có trên mọi distro hiện đại)
// để tự nhận diện OS family/version — KHÔNG bắt buộc điền tay lúc đăng ký
// host nữa (xem app/schemas.py:HostCreate). Trả ("", "") nếu không đọc được
// file hoặc thiếu field ID — KHÔNG fatal, os_family/os_version chỉ ảnh
// hưởng remediate, không ảnh hưởng scan/FIM/heartbeat của Reporter.
//
// Viết hoa ký tự đầu ID ("ubuntu" -> "Ubuntu") để khớp ĐÚNG quy ước
// os_family đang dùng trong RemediationVariant (nhập tay qua Control
// Registry, luôn viết hoa "Ubuntu"/"Debian" — xem tests/test_jobs.py) —
// _find_remediation_variant (app/jobs.py) so khớp CASE-SENSITIVE, lệch hoa
// thường sẽ khiến remediate không tìm thấy variant dù đã khai đúng.
func detectOS(path string) (family, version string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	var id, versionID string
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"`)
		switch key {
		case "ID":
			id = val
		case "VERSION_ID":
			versionID = val
		}
	}
	if id == "" {
		return "", ""
	}
	return strings.ToUpper(id[:1]) + id[1:], versionID
}

// renewalRetryBackoff là khoảng chờ khi 1 lần renew thất bại (mạng lỗi, cert
// hỏng, bị khoá 403, ghi file lỗi...) trước khi thử lại. Cert cũ vẫn còn
// hiệu lực tới tận NotAfter (renew chạy ở NỬA chu kỳ, còn dư nguyên nửa sau
// để retry), nên 1 khoảng cố định ngắn là đủ an toàn — KHÔNG dùng lại luôn
// renewalDeadline() của cert cũ để tính lần thử tiếp theo, vì mốc đó đã ở
// quá khứ (vừa mới tới hạn) và sẽ gây busy-loop gọi /renew liên tục cho tới
// khi thành công hoặc cert hết hạn.
const renewalRetryBackoff = 1 * time.Minute

// renewalDeadline tính mốc renew ở NỬA chu kỳ hiệu lực THẬT của cert hiện
// hành (NotBefore + (NotAfter-NotBefore)/2) — không hardcode 1 khoảng cố
// định như renewalLoop của Agent Manager (4h), để agent tự thích ứng nếu
// provisioner "agent-enrollment" ở step-ca đổi TTL sau này mà không cần sửa
// code/redeploy agent.
func renewalDeadline(leaf *x509.Certificate) time.Time {
	half := leaf.NotAfter.Sub(leaf.NotBefore) / 2
	return leaf.NotBefore.Add(half)
}

// runRenewalLoop chạy song song các vòng lặp khác (heartbeat/scan/FIM), tự
// tính lại mốc renew tiếp theo từ chính cert đang dùng ở đầu mỗi vòng lặp
// (không giữ 1 biến deadline cố định qua các lần lặp) — sau renew thành
// công, holder đã có cert MỚI nên vòng lặp kế tiếp tự động dùng đúng hạn
// mới; renew thất bại thì holder vẫn giữ cert CŨ nên vòng lặp kế tiếp tính
// lại đúng mốc cũ (đã qua), nhưng renewalRetryBackoff phía trên chặn
// busy-loop trong trường hợp đó.
func runRenewalLoop(client *http.Client, certs *certHolder, cfg config) {
	log.Printf("bắt đầu vòng lặp renew cert tới %s", cfg.managerURL)
	for {
		runProtected("renewal-cert", func() { renewalTick(client, certs, cfg) })
	}
}

// renewalTick là 1 lần lặp của runRenewalLoop, tách riêng để runProtected
// bọc được (closure không thể "continue" 1 for-loop ở hàm ngoài) — mọi
// nhánh trước đây dùng "continue" giờ dùng "return", hành vi/thời gian sleep
// giữ NGUYÊN 100%, chỉ khác cách kết thúc 1 lần lặp.
func renewalTick(client *http.Client, certs *certHolder, cfg config) {
	leaf, err := certs.leaf()
	if err != nil {
		log.Printf("renew: không đọc được cert hiện hành để tính hạn renew, thử lại sau %s: %v", renewalRetryBackoff, err)
		time.Sleep(renewalRetryBackoff)
		return
	}

	deadline := renewalDeadline(leaf)
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}

	if err := renewCert(client, certs, cfg); err != nil {
		log.Printf("renew cert thất bại, tiếp tục dùng cert cũ (còn hiệu lực tới %s), thử lại sau %s: %v", leaf.NotAfter, renewalRetryBackoff, err)
		time.Sleep(renewalRetryBackoff)
		return
	}
	log.Printf("renew cert thành công")
}

// renewCert gọi /renew qua Agent Manager, validate cert/key nhận được
// TRƯỚC KHI ghi bất cứ gì xuống đĩa hay hot-swap vào certHolder — mirror
// đúng pattern validate-trước-khi-commit của serverIdentity.refresh() ở
// apps/agent-manager/main.go, để 1 lần renew trả dữ liệu hỏng không làm hại
// cert cũ đang chạy tốt.
func renewCert(client *http.Client, certs *certHolder, cfg config) error {
	reqBody, err := json.Marshal(map[string]string{"hostname": cfg.hostname})
	if err != nil {
		return err
	}
	resp, err := client.Post(cfg.managerURL+"/renew", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("gọi Agent Manager /renew thất bại: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("đọc phản hồi renew thất bại: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent Manager từ chối renew (%d): %s", resp.StatusCode, string(respBody))
	}

	var cr struct {
		CertPEM   string `json:"cert_pem"`
		KeyPEM    string `json:"key_pem"`
		CARootPEM string `json:"ca_root_pem"`
	}
	if err := json.Unmarshal(respBody, &cr); err != nil {
		return fmt.Errorf("phản hồi renew không hợp lệ: %w", err)
	}

	newCert, err := tls.X509KeyPair([]byte(cr.CertPEM), []byte(cr.KeyPEM))
	if err != nil {
		return fmt.Errorf("cert/key renew nhận được không hợp lệ: %w", err)
	}

	// Ghi qua file tạm + os.Rename (atomic trên cùng filesystem) — tránh
	// agent.crt/agent.key nửa-vời nếu process crash giữa chừng ghi, khiến
	// lần khởi động sau đọc phải cert hỏng thay vì tự enroll lại.
	//
	// GAP ĐÃ BIẾT, chấp nhận ở mức hiện tại: mỗi file atomic RIÊNG LẺ, không
	// phải 1 giao dịch chung cho cả 3 — crash đúng lúc GIỮA 2 lần os.Rename
	// (vd sau khi cert.crt đã đổi nhưng agent.key chưa) để lại 1 cặp lệch
	// nhau trên đĩa, khiến buildMTLSClient() lần khởi động sau thất bại (xem
	// message rõ ràng đã thêm ở main() cho trường hợp này — không tự phục
	// hồi được vì bootstrap token gốc đã bị xoá, cần operator tạo token mới).
	// Cách khép kín triệt để (gộp cert+key vào 1 file hoặc đổi sang layout
	// symlink-swap 2 thư mục) đổi hẳn định dạng lưu trữ hiện tại — không làm
	// ở đợt này, cửa sổ rủi ro thực tế chỉ vài instruction giữa 2 syscall
	// rename, cần trúng đúng lúc crash/mất điện để kích hoạt.
	if err := writeFileAtomic(cfg.certPath(), []byte(cr.CertPEM), 0600); err != nil {
		return fmt.Errorf("ghi cert renew thất bại: %w", err)
	}
	if err := writeFileAtomic(cfg.keyPath(), []byte(cr.KeyPEM), 0600); err != nil {
		return fmt.Errorf("ghi key renew thất bại: %w", err)
	}
	if err := writeFileAtomic(cfg.rootPath(), []byte(cr.CARootPEM), 0600); err != nil {
		return fmt.Errorf("ghi ca-root renew thất bại: %w", err)
	}

	// Hot-swap vào client đang chạy — request kế tiếp (kể cả đang xếp hàng)
	// dùng ngay cert mới ở lần handshake tiếp theo, không cần restart process.
	certs.set(newCert)
	return nil
}

// writeFileAtomic ghi data vào file tạm CÙNG thư mục với path rồi
// os.Rename đè lên path thật, để không bao giờ tồn tại 1 file nửa-vời tại
// đường dẫn thật nếu process bị giết giữa chừng ghi.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// postAndExpect POST JSON qua mTLS client và coi MỌI status code khác
// wantStatus là lỗi — dùng chung cho heartbeat/scan-result/fim-event, tránh
// lặp lại logic marshal+post+check-status ở scan.go/fim.go.
func postAndExpect(client *http.Client, url string, payload any, wantStatus int) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Agent Manager từ chối (muốn %d, nhận %d): %s", wantStatus, resp.StatusCode, string(respBody))
	}
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("giá trị %s=%q không hợp lệ, dùng mặc định %s", key, v, def)
		return def
	}
	return d
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getenvList(key string, def []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
