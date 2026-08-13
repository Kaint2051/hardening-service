// Agent Manager — relay mTLS cho Agent tự phát triển (mục 4.3
// architecture-proposal.md). KHÔNG được gọi step-ca trực tiếp ("chỉ
// Orchestrator được gọi CA") — cả cert server của chính nó lẫn mọi thao tác
// enroll/heartbeat/scan-result/fim-event/remediate-* của agent đều đi qua
// Orchestrator bằng shared secret.
//
// Endpoint public (mTLS, nhưng client cert là optional để /enroll dùng được
// trước khi agent có cert):
//   POST /enroll      — chưa cần client cert, relay {hostname, token} sang
//                        Orchestrator để đổi lấy cert mTLS thật.
//   POST /heartbeat, /scan-result, /fim-event, /host-metrics,
//        /remediate-jobs/claim, /remediation-bundle, /remediate-result,
//        /restore-result — BẮT BUỘC client cert hợp
//                        lệ; CN trong cert (do chính step-ca ký) phải khớp
//                        hostname trong body, không tin hostname client tự
//                        khai nếu không khớp cert (xem handleMTLSRelay). 3
//                        route remediate-* (Active Response) dùng chung
//                        handler này, chỉ khác maxBytes cho phép (xem
//                        maxRemediateResultBodyBytes) vì /remediate-result
//                        có thể mang theo backup đã base64-encode.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const serverCertSubject = "agent-manager"

type certResponse struct {
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	CARootPEM string `json:"ca_root_pem"`
}

// serverIdentity giữ cert/key/root hiện hành của chính Agent Manager, hot-
// reload được qua renewalLoop mà không cần restart process (tls.Config dùng
// GetConfigForClient để đọc lại tại mỗi handshake thay vì đóng băng 1 lần).
type serverIdentity struct {
	mu        sync.RWMutex
	certPEM   []byte
	keyPEM    []byte
	caRootPEM []byte

	// Trạng thái lần renew (refresh) gần nhất — phục vụ GET /metrics (mục
	// "Chưa expose metric Prometheus" trong README), KHÔNG ảnh hưởng logic
	// mTLS chính (chỉ đọc để báo cáo). Ghi trong refresh() (wrapper bên dưới,
	// không phải doRefresh) nên áp dụng cho MỌI lần gọi refresh(), kể cả từ
	// waitForServerCert lúc khởi động.
	lastRenewSuccess bool
	lastRenewAt      time.Time
}

// refresh gọi doRefresh() rồi luôn ghi lại kết quả (thành công hay lỗi) vào
// lastRenewSuccess/lastRenewAt trước khi trả lỗi ra ngoài — tách riêng khỏi
// doRefresh (giữ nguyên logic gốc, không đổi) để không phải sửa lại các điểm
// return rải rác bên trong.
func (s *serverIdentity) refresh(orchestratorURL, secret string) error {
	err := s.doRefresh(orchestratorURL, secret)
	s.mu.Lock()
	s.lastRenewSuccess = err == nil
	s.lastRenewAt = time.Now()
	s.mu.Unlock()
	return err
}

// renewalStatus đọc lại trạng thái do refresh() ghi — an toàn gọi đồng thời
// với renewalLoop() đang chạy nền.
func (s *serverIdentity) renewalStatus() (success bool, at time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRenewSuccess, s.lastRenewAt
}

func (s *serverIdentity) doRefresh(orchestratorURL, secret string) error {
	req, err := http.NewRequest(http.MethodPost, orchestratorURL+"/internal/agent-manager/server-cert", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gọi Orchestrator xin server cert thất bại: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("đọc phản hồi server cert thất bại: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Orchestrator từ chối cấp server cert (%d): %s", resp.StatusCode, string(body))
	}

	var cr certResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return fmt.Errorf("phản hồi server cert không hợp lệ: %w", err)
	}

	// Validate trước khi commit — không ghi đè cert đang dùng bằng dữ liệu hỏng,
	// để 1 lần renew lỗi không làm sập mTLS đang chạy tốt.
	if _, err := tls.X509KeyPair([]byte(cr.CertPEM), []byte(cr.KeyPEM)); err != nil {
		return fmt.Errorf("cert/key nhận được không hợp lệ: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cr.CARootPEM)) {
		return fmt.Errorf("ca_root_pem nhận được không hợp lệ")
	}

	s.mu.Lock()
	s.certPEM = []byte(cr.CertPEM)
	s.keyPEM = []byte(cr.KeyPEM)
	s.caRootPEM = []byte(cr.CARootPEM)
	s.mu.Unlock()
	return nil
}

func (s *serverIdentity) tlsConfigSnapshot() (*tls.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.certPEM) == 0 {
		return nil, fmt.Errorf("chưa có server cert")
	}
	cert, err := tls.X509KeyPair(s.certPEM, s.keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.caRootPEM)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		// Optional (không Require) vì /enroll phải hoạt động được TRƯỚC khi
		// agent có client cert — /heartbeat tự kiểm tra cert trong handler.
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// waitForServerCert thử refresh() lặp lại cách nhau `interval` cho tới khi
// thành công hoặc vượt quá `deadline` tổng — trả lỗi cuối cùng nếu hết hạn.
func waitForServerCert(ident *serverIdentity, orchestratorURL, secret string, interval, deadline time.Duration) error {
	giveUpAt := time.Now().Add(deadline)
	var lastErr error
	for {
		lastErr = ident.refresh(orchestratorURL, secret)
		if lastErr == nil {
			return nil
		}
		if time.Now().After(giveUpAt) {
			return lastErr
		}
		log.Printf("chưa lấy được server cert (Orchestrator có thể đang khởi động), thử lại sau %s: %v", interval, lastErr)
		time.Sleep(interval)
	}
}

func (s *serverIdentity) renewalLoop(orchestratorURL, secret string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := s.refresh(orchestratorURL, secret); err != nil {
			log.Printf("renew server cert thất bại, tiếp tục dùng cert cũ: %v", err)
			continue
		}
		log.Printf("renew server cert thành công")
	}
}

type enrollRequest struct {
	Hostname string `json:"hostname"`
	Token    string `json:"token"`
}

// maxRequestBodyBytes chặn 1 client (kể cả chưa xác thực — /enroll không
// yêu cầu client cert) gửi body khổng lồ để làm cạn bộ nhớ; 1 MiB dư sức cho
// envelope lớn nhất thực tế (result_summary.findings của scan-result, ước
// lượng vài trăm rule x vài trăm byte/rule vẫn dưới ngưỡng này rất nhiều).
const maxRequestBodyBytes = 1 << 20

// maxRemediateResultBodyBytes áp dụng riêng cho /remediate-result — báo cáo
// kết quả remediation có thể mang theo backup_tar_b64 (tối đa BACKUP_MAX_BYTES
// = 2 MiB ở Orchestrator, xem jobs.py) đã base64-encode (phình lên ~2.7 MiB),
// cộng overhead JSON của các field còn lại (diff_output, log_tail, error...).
// 4 MiB dư sức cho toàn bộ payload này mà KHÔNG nới lỏng maxRequestBodyBytes
// (1 MiB) đang áp dụng cho mọi route JSON nhỏ khác (heartbeat/scan-result/
// fim-event/renew/remediate-jobs-claim/remediation-bundle).
const maxRemediateResultBodyBytes = 4 << 20

// defaultRelayTimeout áp dụng cho mọi route relay JSON nhỏ (heartbeat/scan-
// result/fim-event/renew/remediate-jobs-claim/remediate-result) — đủ rộng
// rãi cho payload cỡ này trên kết nối bình thường.
const defaultRelayTimeout = 15 * time.Second

// bundleRelayTimeout áp dụng RIÊNG cho /remediation-bundle — trước đây route
// này dùng chung defaultRelayTimeout (15s) dù có thể mang bundle content lớn
// hơn nhiều JSON nhỏ khác, khiến CHÍNH relay này (không phải phía Reporter
// hay Executor) trở thành ràng buộc chặt nhất trong cả dây chuyền tải bundle
// — chặt hơn cả timeout Reporter tự cho phép phía nó (apps/agent/pki.go:
// buildMTLSClient, 30s cho toàn bộ vòng đời request kể cả relay qua đây),
// dù maxBundleResponseBytes (apps/agent/remediate.go, 64 MiB) cho phép bundle
// lớn hơn nhiều so với những gì 15s tải xong được trên kết nối không phải
// LAN cực nhanh (phát hiện qua rà soát đối kháng riêng cho subsystem Agent).
// Khớp đúng bằng thời gian Reporter tự cho phép — không có lý do đặt dài hơn
// vì Reporter bỏ cuộc ở mốc đó bất kể relay này có chờ thêm hay không.
const bundleRelayTimeout = 30 * time.Second

// rateLimiter giới hạn tần suất request THEO HOSTNAME (định danh đã xác thực
// qua CN cert — không theo IP, vì agent có thể đứng sau NAT chung IP với
// agent khác). Dùng CHUNG 1 instance cho mọi endpoint relay (heartbeat/
// scan-result/fim-event/renew, xem main()) — 1 agent lỗi/bị compromise dồn
// dập bất kỳ endpoint nào cũng bị tính vào cùng 1 ngưỡng, tránh lách bằng
// cách rải request qua nhiều endpoint khác nhau.
//
// Tự viết token bucket thay vì thêm dependency ngoài (vd golang.org/x/time/
// rate): go.mod hiện tại CHỦ ĐÍCH không có dependency nào — agent-manager là
// mặt tiếp xúc trực tiếp LAN duy nhất (publish port, xem docker-compose.yml),
// giữ tối giản bề mặt tấn công; thuật toán chỉ vài dòng, không đáng đánh đổi
// thêm 1 module ngoài.
//
// Không cần dọn bucket cũ theo thời gian — map chỉ lớn tới đúng số host thật
// đã enroll, giới hạn ≤50 theo quyết định quy mô ban đầu của dự án (xem
// README gốc mục 0), không có nguy cơ phình bộ nhớ.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // token nạp lại mỗi giây
	burst   float64 // sức chứa tối đa (cũng là số request cho qua ngay lúc mới thấy 1 hostname)
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*tokenBucket), rate: rate, burst: burst}
}

// allow tiêu tốn đúng 1 token nếu còn, trả false (và không tiêu token) nếu
// hostname đã vượt tốc độ cho phép.
func (rl *rateLimiter) allow(hostname string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[hostname]
	if !ok {
		b = &tokenBucket{tokens: rl.burst, lastRefill: now}
		rl.buckets[hostname] = b
	}
	b.tokens += now.Sub(b.lastRefill).Seconds() * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastRefill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// hostCount trả số hostname khác nhau đã từng gọi allow() ít nhất 1 lần —
// dùng làm proxy cho "số agent đã từng liên lạc với agent-manager" ở
// GET /metrics (map không tự dọn theo thời gian, xem comment tại struct
// rateLimiter, nên đây là số ĐÃ TỪNG thấy, không phải số đang "online" tức
// thời — không có khái niệm "đang connect" vì mỗi request là 1 lần gọi HTTP
// rời rạc, không giữ kết nối lâu dài).
func (rl *rateLimiter) hostCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// relayRateLimit/relayRateBurst: lưu lượng hợp lệ thực tế rất thấp (mặc định
// heartbeat 60s/lần, FIM 5 phút/lần chỉ báo file thật sự đổi, renew nửa chu kỳ
// TTL cert ~4h — xem apps/agent/main.go) nên burst=20 + refill 1 token/2s
// (30 request/phút bền vững) đã rộng rãi hơn nhiều so với nhu cầu thật, trong
// khi vẫn chặn được 1 agent lỗi/bị compromise dồn dập ở tần suất bất thường.
const (
	relayRateLimit = 0.5 // token/giây
	relayRateBurst = 20
)

// writeBodyDecodeError phân biệt "body vượt maxRequestBodyBytes" (413, đúng
// mã lỗi HTTP cho trường hợp này) với "body chỉ đơn giản là JSON hỏng"
// (dùng thông điệp genericMsg của caller, giữ nguyên hành vi cũ).
func writeBodyDecodeError(w http.ResponseWriter, err error, genericMsg string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, `{"detail":"body vượt quá giới hạn cho phép"}`, http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, fmt.Sprintf(`{"detail":%q}`, genericMsg), http.StatusBadRequest)
}

func handleEnroll(orchestratorURL, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"detail":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var body enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeBodyDecodeError(w, err, "thiếu hostname hoặc token")
			return
		}
		if body.Hostname == "" || body.Token == "" {
			http.Error(w, `{"detail":"thiếu hostname hoặc token"}`, http.StatusBadRequest)
			return
		}
		relayJSON(w, orchestratorURL+"/internal/agent/verify-and-enroll", secret, body, defaultRelayTimeout)
	}
}

// handleMTLSRelay dựng handler chung cho MỌI endpoint bắt buộc client cert
// (heartbeat, scan-result, fim-event, remediate-jobs/claim, remediation-
// bundle, remediate-result) — thân body mỗi loại khác nhau (scan-result có
// result_summary lồng nhau tuỳ ý, remediate-result có thể mang backup lớn),
// nên decode vào map[string]any thay vì struct riêng cho từng loại, chỉ cần
// đọc "hostname" để so khớp CN. maxBytes tham số hoá theo từng route (xem
// maxRequestBodyBytes vs maxRemediateResultBodyBytes) — route nào mang theo
// backup base64 cần trần cao hơn, các route JSON nhỏ khác giữ nguyên 1 MiB.
//
// Wrapper mỏng quanh handleMTLSRelayWithTimeout (dùng defaultRelayTimeout) —
// giữ nguyên chữ ký cũ để KHÔNG phải sửa lại ~20 lời gọi test hiện có chỉ vì
// 1 route (/remediation-bundle) cần timeout khác, xem đăng ký route bên dưới
// (mux.HandleFunc) gọi thẳng handleMTLSRelayWithTimeout cho riêng route đó.
func handleMTLSRelay(orchestratorPath, secret string, limiter *rateLimiter, maxBytes int64) http.HandlerFunc {
	return handleMTLSRelayWithTimeout(orchestratorPath, secret, limiter, maxBytes, defaultRelayTimeout)
}

func handleMTLSRelayWithTimeout(
	orchestratorPath, secret string, limiter *rateLimiter, maxBytes int64, timeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"detail":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeBodyDecodeError(w, err, "body không phải JSON hợp lệ")
			return
		}
		hostname, _ := body["hostname"].(string)
		if hostname == "" {
			http.Error(w, `{"detail":"thiếu hostname"}`, http.StatusBadRequest)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"detail":"yêu cầu client cert mTLS"}`, http.StatusUnauthorized)
			return
		}
		// CN do step-ca ký lúc enroll (xem mint_agent_client_cert) — nguồn sự
		// thật duy nhất cho danh tính. Không tin "hostname" client tự khai
		// trong body nếu không khớp CN, tránh 1 agent giả mạo report cho
		// host khác dù đã có cert hợp lệ của chính mình.
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		if !strings.EqualFold(cn, hostname) {
			http.Error(w, `{"detail":"hostname không khớp client cert"}`, http.StatusForbidden)
			return
		}
		// Giới hạn theo CN đã xác thực (không phải hostname client tự khai,
		// dù 2 giá trị đã khớp nhau ở trên) — dùng chung 1 bucket cho mọi
		// endpoint relay, xem comment tại rateLimiter.
		if !limiter.allow(strings.ToLower(cn)) {
			http.Error(w, `{"detail":"quá nhiều request, thử lại sau"}`, http.StatusTooManyRequests)
			return
		}
		// So khớp CN↔hostname ở trên là case-INSENSITIVE (EqualFold), nhưng
		// body["hostname"] vẫn giữ NGUYÊN chuỗi client tự gõ (case tuỳ ý) —
		// nếu relay thẳng map `body` như cũ, Orchestrator (Host.hostname là
		// primary key case-SENSITIVE, mọi so khớp Job.hostname==/!= ở
		// app/agents.py cũng case-sensitive) sẽ tin ĐÚNG chuỗi hostname
		// client khai, không phải CN đã xác thực bằng crypto — 1 agent hợp
		// lệ (CN="WebServer01") có thể tự khai hostname="webserver01" để
		// claim/report job của 1 host KHÁC chỉ khác hoa/thường (phát hiện
		// qua rà soát đối kháng: register_host không chặn tạo 2 host
		// case-variant của nhau). Ghi đè lại bằng CN đã xác thực TRƯỚC khi
		// relay — Orchestrator từ nay luôn nhận đúng danh tính
		// cryptographic, không bao giờ nhận chuỗi hostname client tự chọn.
		body["hostname"] = cn
		relayJSON(w, orchestratorPath, secret, body, timeout)
	}
}

func relayJSON(w http.ResponseWriter, url, secret string, payload any, timeout time.Duration) {
	buf, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"detail":"lỗi nội bộ agent-manager"}`, http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		http.Error(w, `{"detail":"lỗi nội bộ agent-manager"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	httpClient := &http.Client{Timeout: timeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, `{"detail":"không gọi được Orchestrator"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// metrics đếm số request đã relay theo (endpoint, status code) — mục "Chưa
// expose metric Prometheus" trong README. Tự viết format text Prometheus
// bằng tay (rất đơn giản: `tên{nhãn} giá_trị`) thay vì thêm thư viện
// prometheus/client_golang — cùng lý do rateLimiter tự viết token bucket:
// go.mod cố tình không có dependency ngoài, agent-manager là mặt tiếp xúc
// LAN duy nhất publish port.
type metrics struct {
	mu    sync.Mutex
	count map[string]map[int]uint64 // endpoint -> status code -> số lần
}

func newMetrics() *metrics {
	return &metrics{count: make(map[string]map[int]uint64)}
}

func (m *metrics) recordRelay(endpoint string, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.count[endpoint] == nil {
		m.count[endpoint] = make(map[int]uint64)
	}
	m.count[endpoint][status]++
}

func (m *metrics) snapshot() map[string]map[int]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]map[int]uint64, len(m.count))
	for endpoint, byStatus := range m.count {
		out[endpoint] = make(map[int]uint64, len(byStatus))
		for status, n := range byStatus {
			out[endpoint][status] = n
		}
	}
	return out
}

// statusRecorder bọc http.ResponseWriter chỉ để nhớ lại status code cuối
// cùng đã ghi — cho phép metricsMiddleware đếm request theo status mà KHÔNG
// phải sửa handleEnroll/handleMTLSRelay/relayJSON (đã có hơn chục lời gọi
// trong main_test.go, đổi chữ ký sẽ phải sửa lại toàn bộ chỉ để thêm 1 tính
// năng quan sát, không đáng).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// metricsMiddleware bọc NGOÀI 1 handler đã có, không đụng gì vào logic bên
// trong (rate limit, so khớp CN, relay...) — chỉ đăng ký thêm ở main(), nên
// không ảnh hưởng bộ test hiện có của các handler đó.
func metricsMiddleware(endpoint string, m *metrics, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		m.recordRelay(endpoint, rec.status)
	}
}

// handleMetrics expose Prometheus text format (đủ để `docker exec ... curl`/
// Prometheus scrape đọc được, không cần header đặc biệt gì thêm ngoài
// Content-Type text/plain). KHÔNG yêu cầu xác thực — cùng mức lộ thông tin
// như /healthz hiện có (chỉ số liệu tổng hợp: đếm request/trạng thái renew,
// KHÔNG có hostname cụ thể nào), phù hợp quy ước Prometheus tiêu chuẩn (hầu
// hết exporter không tự làm auth, để lớp mạng lo việc đó) — chấp nhận được
// dù agent-manager publish thẳng port ra LAN.
func handleMetrics(m *metrics, limiter *rateLimiter, ident *serverIdentity) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		fmt.Fprintln(w, "# HELP agent_manager_relay_requests_total Tổng số request relay theo endpoint và mã trạng thái HTTP trả về cho client")
		fmt.Fprintln(w, "# TYPE agent_manager_relay_requests_total counter")
		for endpoint, byStatus := range m.snapshot() {
			for status, n := range byStatus {
				fmt.Fprintf(w, "agent_manager_relay_requests_total{endpoint=%q,status=\"%d\"} %d\n", endpoint, status, n)
			}
		}

		fmt.Fprintln(w, "# HELP agent_manager_known_hosts Số hostname khác nhau đã từng gọi endpoint relay (không tự dọn theo thời gian, xem rateLimiter)")
		fmt.Fprintln(w, "# TYPE agent_manager_known_hosts gauge")
		fmt.Fprintf(w, "agent_manager_known_hosts %d\n", limiter.hostCount())

		success, at := ident.renewalStatus()
		successVal := 0
		if success {
			successVal = 1
		}
		fmt.Fprintln(w, "# HELP agent_manager_server_cert_renewal_success Lần renew cert gần nhất của CHÍNH agent-manager có thành công không (1=có, 0=không; 0 nếu chưa renew lần nào)")
		fmt.Fprintln(w, "# TYPE agent_manager_server_cert_renewal_success gauge")
		fmt.Fprintf(w, "agent_manager_server_cert_renewal_success %d\n", successVal)
		if !at.IsZero() {
			fmt.Fprintln(w, "# HELP agent_manager_server_cert_renewal_timestamp_seconds Unix timestamp lần renew cert gần nhất (thành công hoặc thất bại)")
			fmt.Fprintln(w, "# TYPE agent_manager_server_cert_renewal_timestamp_seconds gauge")
			fmt.Fprintf(w, "agent_manager_server_cert_renewal_timestamp_seconds %d\n", at.Unix())
		}
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("thiếu biến môi trường bắt buộc: %s", key)
	}
	return v
}

func main() {
	// Cổng 8001 (KHÔNG phải 8000 — đó là cổng HTTPS browser-facing của
	// Orchestrator, xem apps/orchestrator/app/serve.py), khớp đúng giá trị
	// docker-compose.yml luôn set qua ORCHESTRATOR_URL — default này chỉ dùng
	// khi biến môi trường đó bị thiếu, giữ đúng convention thay vì trỏ nhầm
	// sang cổng browser-facing.
	orchestratorURL := getenv("ORCHESTRATOR_URL", "http://orchestrator:8001")
	sharedSecret := mustGetenv("AGENT_MANAGER_SHARED_SECRET")
	listenAddr := getenv("AGENT_MANAGER_LISTEN_ADDR", ":8443")

	ident := &serverIdentity{}
	// Lấy cert lần đầu blocking lúc khởi động — Agent Manager vô nghĩa nếu
	// không có cert để mTLS. Retry với backoff cố định thay vì Fatal ngay ở
	// lần thử đầu: phát hiện thật khi deploy — depends_on:service_started
	// chỉ đảm bảo container orchestrator đã start, KHÔNG đảm bảo alembic
	// migrate + uvicorn đã sẵn sàng nhận request, nên lần thử đầu luôn thất
	// bại lúc mới `docker compose up`. Chỉ Fatal khi đã thử đủ lâu để phân
	// biệt "chưa sẵn sàng" (transient) với "thật sự hỏng" (CA/cấu hình sai).
	if err := waitForServerCert(ident, orchestratorURL, sharedSecret, 2*time.Second, 60*time.Second); err != nil {
		log.Fatalf("không lấy được server cert sau nhiều lần thử: %v", err)
	}
	// Provisioner "agent-enrollment" cấp x509 mặc định 8h (xem
	// infra/step-ca/setup-provisioners.sh) — renew ở nửa chu kỳ để luôn còn
	// dư thời gian nếu 1-2 lần renew đầu thất bại tạm thời.
	go ident.renewalLoop(orchestratorURL, sharedSecret, 4*time.Hour)

	// 1 instance dùng chung cho mọi endpoint relay bên dưới — xem comment tại
	// rateLimiter (mục "chưa có rate-limit/backoff" trong README).
	relayLimiter := newRateLimiter(relayRateLimit, relayRateBurst)
	metricsStore := newMetrics()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handleMetrics(metricsStore, relayLimiter, ident))
	mux.HandleFunc("/enroll", metricsMiddleware("enroll", metricsStore, handleEnroll(orchestratorURL, sharedSecret)))
	mux.HandleFunc("/heartbeat", metricsMiddleware("heartbeat", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/heartbeat", sharedSecret, relayLimiter, maxRequestBodyBytes)))
	mux.HandleFunc("/scan-result", metricsMiddleware("scan-result", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/scan-result", sharedSecret, relayLimiter, maxRequestBodyBytes)))
	mux.HandleFunc("/fim-event", metricsMiddleware("fim-event", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/fim-event", sharedSecret, relayLimiter, maxRequestBodyBytes)))
	mux.HandleFunc("/renew", metricsMiddleware("renew", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/renew-cert", sharedSecret, relayLimiter, maxRequestBodyBytes)))
	// "/host-metrics" (KHÔNG phải "/metrics" — route đó ở trên là Prometheus
	// tự-giám-sát của chính agent-manager) — CPU/RAM/Disk/Network do Agent
	// tự đo, xem apps/agent/metrics.go.
	mux.HandleFunc("/host-metrics", metricsMiddleware("host-metrics", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/host-metrics", sharedSecret, relayLimiter, maxRequestBodyBytes)))
	// "/restore-result" — job "restore" dùng CHUNG /remediate-jobs/claim bên
	// dưới để nhận việc (job_kind trong response phân biệt), nhưng báo kết
	// quả qua route RIÊNG này (shape khác /remediate-result — không backup
	// mới, xem apps/agent/restore.go, app/agents.py:report_restore_result).
	mux.HandleFunc("/restore-result", metricsMiddleware("restore-result", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/restore-result", sharedSecret, relayLimiter, maxRequestBodyBytes)))

	// Active Response: relay generic hệt các route trên, tham số hoá maxBytes
	// khác nhau theo nhu cầu từng route (xem comment tại maxRemediateResultBodyBytes).
	mux.HandleFunc("/remediate-jobs/claim", metricsMiddleware("remediate-jobs-claim", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/remediate-jobs/claim", sharedSecret, relayLimiter, maxRequestBodyBytes)))
	mux.HandleFunc("/remediation-bundle", metricsMiddleware("remediation-bundle", metricsStore, handleMTLSRelayWithTimeout(orchestratorURL+"/internal/agent/remediation-bundle", sharedSecret, relayLimiter, maxRequestBodyBytes, bundleRelayTimeout)))
	mux.HandleFunc("/remediate-result", metricsMiddleware("remediate-result", metricsStore, handleMTLSRelay(orchestratorURL+"/internal/agent/remediate-result", sharedSecret, relayLimiter, maxRemediateResultBodyBytes)))

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
		// Zero-value net/http.Server có timeout = vô hạn — 1 client (kể cả
		// chưa xác thực, /enroll không yêu cầu client cert) gửi header/body
		// nhỏ giọt (Slowloris) hoặc giữ kết nối mở vô thời hạn có thể làm
		// cạn goroutine/file descriptor, vì agent-manager publish thẳng ra
		// LAN (không có reverse proxy đứng trước) — phát hiện qua rà soát
		// bảo mật, không phải test thật (test hiện gọi handler trực tiếp
		// qua httptest, không đi qua http.Server thật nên không lộ ra).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			// http.Server.ServeTLS chỉ bỏ qua LoadX509KeyPair("","") khi
			// config.Certificates hoặc config.GetCertificate được set — nó
			// KHÔNG biết tới GetConfigForClient khi kiểm tra điều kiện này,
			// nên phải set cả GetCertificate (dù per-connection thật sự
			// dùng snapshot trả về từ GetConfigForClient bên dưới) — thiếu
			// dòng này khiến MỌI kết nối lỗi "open : no such file or
			// directory" dù renew cert thành công (phát hiện qua test live
			// trên lab server, không phải chỉ đọc code).
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cfg, err := ident.tlsConfigSnapshot()
				if err != nil {
					return nil, err
				}
				return &cfg.Certificates[0], nil
			},
			GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
				return ident.tlsConfigSnapshot()
			},
		},
	}

	log.Printf("agent-manager nghe mTLS tại %s (subject cert server: %s)", listenAddr, serverCertSubject)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
