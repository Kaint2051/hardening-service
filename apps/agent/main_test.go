package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	os.WriteFile(present, []byte("x"), 0600)
	if !fileExists(present) {
		t.Fatalf("fileExists(%q) = false, muốn true", present)
	}
	if fileExists(filepath.Join(dir, "missing")) {
		t.Fatalf("fileExists cho file không tồn tại = true, muốn false")
	}
}

func TestGetenvDuration(t *testing.T) {
	t.Setenv("AGENT_TEST_INTERVAL", "2m")
	if got := getenvDuration("AGENT_TEST_INTERVAL", time.Second); got != 2*time.Minute {
		t.Fatalf("getenvDuration = %s, muốn 2m", got)
	}
}

func TestGetenvDuration_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv("AGENT_TEST_INTERVAL", "not-a-duration")
	if got := getenvDuration("AGENT_TEST_INTERVAL", 5*time.Second); got != 5*time.Second {
		t.Fatalf("getenvDuration với giá trị hỏng = %s, muốn fallback 5s", got)
	}
}

func TestGetenvDuration_UnsetUsesDefault(t *testing.T) {
	os.Unsetenv("AGENT_TEST_INTERVAL_UNSET")
	if got := getenvDuration("AGENT_TEST_INTERVAL_UNSET", 5*time.Second); got != 5*time.Second {
		t.Fatalf("getenvDuration khi biến chưa set = %s, muốn 5s", got)
	}
}

// upstreamCertServerName là SAN có sẵn trong cert self-signed mặc định của
// httptest.NewTLSServer (net/http/internal/testcert) — dùng làm ServerName
// để agent verify được server test qua chính cert của nó (trust trực tiếp
// leaf cert làm root, không cần dựng CA giả riêng cho test).
const upstreamCertServerName = "example.com"

func writeTestRootCert(t *testing.T, dir string, srv *httptest.Server) string {
	t.Helper()
	rootPath := filepath.Join(dir, "ca-root.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(rootPath, pemBytes, 0600); err != nil {
		t.Fatalf("ghi ca-root.crt test thất bại: %v", err)
	}
	return rootPath
}

func TestEnroll_SuccessWritesCertFilesAndRemovesToken(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll" {
			t.Errorf("path = %q, muốn /enroll", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"cert_pem":"CERT-DATA","key_pem":"KEY-DATA","ca_root_pem":"ROOT-DATA"}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	writeTestRootCert(t, dir, upstream)
	tokenPath := filepath.Join(dir, "enroll-token")
	os.WriteFile(tokenPath, []byte("bootstrap-token-123\n"), 0600)

	cfg := config{
		managerURL:     upstream.URL,
		managerTLSName: upstreamCertServerName,
		hostname:       "agent-test-host",
		stateDir:       dir,
	}
	if err := enroll(cfg); err != nil {
		t.Fatalf("enroll() lỗi: %v", err)
	}

	certBytes, err := os.ReadFile(cfg.certPath())
	if err != nil || string(certBytes) != "CERT-DATA" {
		t.Fatalf("agent.crt = %q, err=%v, muốn CERT-DATA", certBytes, err)
	}
	keyBytes, _ := os.ReadFile(cfg.keyPath())
	if string(keyBytes) != "KEY-DATA" {
		t.Fatalf("agent.key = %q, muốn KEY-DATA", keyBytes)
	}
	if fileExists(tokenPath) {
		t.Fatalf("token file vẫn còn tồn tại sau enroll thành công — phải bị xoá")
	}
}

func TestEnroll_MissingTokenFileFails(t *testing.T) {
	dir := t.TempDir()
	cfg := config{stateDir: dir, hostname: "h", managerURL: "https://unused", managerTLSName: "x"}
	// Chưa ghi ca-root.crt lẫn enroll-token — phải lỗi ngay ở bước đọc token,
	// không phải panic hay treo cố gắng dial mạng.
	if err := enroll(cfg); err == nil {
		t.Fatalf("enroll() không lỗi dù thiếu token file")
	}
}

func TestEnroll_UpstreamRejectionSurfacesError(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"token đã được dùng"}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	writeTestRootCert(t, dir, upstream)
	os.WriteFile(filepath.Join(dir, "enroll-token"), []byte("used-token"), 0600)

	cfg := config{
		managerURL:     upstream.URL,
		managerTLSName: upstreamCertServerName,
		hostname:       "agent-test-host",
		stateDir:       dir,
	}
	err := enroll(cfg)
	if err == nil {
		t.Fatalf("enroll() không lỗi dù Agent Manager trả 401")
	}
	if fileExists(cfg.certPath()) {
		t.Fatalf("agent.crt không được tạo khi enroll thất bại")
	}
}

func TestHeartbeat_SuccessOnNoContent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	if err := heartbeat(upstream.Client(), upstream.URL, "h1", "", ""); err != nil {
		t.Fatalf("heartbeat() lỗi: %v", err)
	}
}

func TestHeartbeat_NonNoContentIsError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"detail":"host không tồn tại"}`))
	}))
	defer upstream.Close()

	if err := heartbeat(upstream.Client(), upstream.URL, "h1", "", ""); err == nil {
		t.Fatalf("heartbeat() không lỗi dù Agent Manager trả 404")
	}
}

func TestHeartbeat_IncludesOSFieldsWhenDetected(t *testing.T) {
	var gotBody map[string]string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	if err := heartbeat(upstream.Client(), upstream.URL, "h1", "Ubuntu", "22.04"); err != nil {
		t.Fatalf("heartbeat() lỗi: %v", err)
	}
	if gotBody["os_family"] != "Ubuntu" || gotBody["os_version"] != "22.04" {
		t.Fatalf("body heartbeat = %+v, muốn os_family=Ubuntu os_version=22.04", gotBody)
	}
}

// TestHeartbeat_OmitsOSFieldsWhenNotDetected xác nhận detectOS thất bại
// (osFamily/osVersion rỗng) không gửi field rỗng lên Orchestrator — thiếu
// HẲN key, không phải "" — vì agent_heartbeat (app/agents.py) chỉ cập nhật
// khi field CÓ MẶT và khác rỗng; gửi "" vô hại về mặt logic backend nhưng
// thiếu key rõ ràng hơn cho việc đọc log/debug request thật.
func TestHeartbeat_OmitsOSFieldsWhenNotDetected(t *testing.T) {
	var gotBody map[string]string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	if err := heartbeat(upstream.Client(), upstream.URL, "h1", "", ""); err != nil {
		t.Fatalf("heartbeat() lỗi: %v", err)
	}
	if _, ok := gotBody["os_family"]; ok {
		t.Fatalf("body heartbeat chứa os_family dù detectOS không nhận diện được: %+v", gotBody)
	}
	if _, ok := gotBody["os_version"]; ok {
		t.Fatalf("body heartbeat chứa os_version dù detectOS không nhận diện được: %+v", gotBody)
	}
}

func TestDetectOS_ParsesIDAndVersionID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	os.WriteFile(path, []byte("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n"), 0600)

	family, version := detectOS(path)
	if family != "Ubuntu" || version != "22.04" {
		t.Fatalf("detectOS() = (%q, %q), muốn (Ubuntu, 22.04)", family, version)
	}
}

func TestDetectOS_CapitalizesLowercaseID(t *testing.T) {
	// _find_remediation_variant (app/jobs.py) so khớp os_family CASE-
	// SENSITIVE, RemediationVariant nhập tay luôn viết hoa ("Debian") —
	// detectOS phải khớp đúng quy ước đó dù /etc/os-release luôn ghi ID viết
	// thường theo chuẩn systemd.
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	os.WriteFile(path, []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0600)

	family, _ := detectOS(path)
	if family != "Debian" {
		t.Fatalf("detectOS() family = %q, muốn Debian (viết hoa ký tự đầu)", family)
	}
}

func TestDetectOS_MissingFileReturnsEmpty(t *testing.T) {
	family, version := detectOS(filepath.Join(t.TempDir(), "missing-os-release"))
	if family != "" || version != "" {
		t.Fatalf("detectOS() cho file không tồn tại = (%q, %q), muốn (\"\", \"\")", family, version)
	}
}

func TestDetectOS_MissingIDLineReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	// Có VERSION_ID nhưng thiếu ID — không đủ để xác định os_family, phải
	// coi như không nhận diện được (không trả version mồ côi không có family).
	os.WriteFile(path, []byte("VERSION_ID=\"22.04\"\n"), 0600)

	family, version := detectOS(path)
	if family != "" || version != "" {
		t.Fatalf("detectOS() thiếu ID = (%q, %q), muốn (\"\", \"\")", family, version)
	}
}

func TestRenewalDeadline_ComputesMidpointOfValidity(t *testing.T) {
	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(8 * time.Hour)
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}

	got := renewalDeadline(leaf)
	want := notBefore.Add(4 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("renewalDeadline = %s, muốn đúng điểm giữa %s (NotBefore + (NotAfter-NotBefore)/2)", got, want)
	}
}

// TestRenewalDeadline_AdaptsToDifferentValidityWindow xác nhận renewalDeadline
// tính LẠI từ chính cert (không hardcode 1 khoảng cố định như renewalLoop
// của Agent Manager) — 1 cửa sổ hiệu lực hoàn toàn khác (30 phút, không phải
// hàng giờ) vẫn phải ra đúng điểm giữa TƯƠNG ỨNG, mô phỏng đúng tình huống
// provisioner "agent-enrollment" ở step-ca đổi TTL mà không cần sửa/redeploy
// code agent.
func TestRenewalDeadline_AdaptsToDifferentValidityWindow(t *testing.T) {
	notBefore := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(30 * time.Minute)
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}

	got := renewalDeadline(leaf)
	want := notBefore.Add(15 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("renewalDeadline = %s, muốn %s", got, want)
	}
}

func TestRenewCert_SuccessValidatesWritesFilesAndHotSwaps(t *testing.T) {
	oldCertPEM, oldKeyPEM := generateTestCertPEM(t, "agent-old", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	newCertPEM, newKeyPEM := generateTestCertPEM(t, "agent-new", time.Now(), time.Now().Add(8*time.Hour))
	const newRootPEM = "NEW-ROOT-PEM-DATA"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/renew" {
			t.Errorf("path = %q, muốn /renew", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body renew không phải JSON hợp lệ: %v", err)
		}
		if body["hostname"] != "agent-test-host" {
			t.Errorf("hostname trong request renew = %q, muốn agent-test-host", body["hostname"])
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem":    newCertPEM,
			"key_pem":     newKeyPEM,
			"ca_root_pem": newRootPEM,
		})
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := config{managerURL: upstream.URL, hostname: "agent-test-host", stateDir: dir}
	os.WriteFile(cfg.certPath(), []byte(oldCertPEM), 0600)
	os.WriteFile(cfg.keyPath(), []byte(oldKeyPEM), 0600)
	os.WriteFile(cfg.rootPath(), []byte("OLD-ROOT-PEM-DATA"), 0600)

	oldCert, err := tls.X509KeyPair([]byte(oldCertPEM), []byte(oldKeyPEM))
	if err != nil {
		t.Fatalf("dựng old cert test thất bại: %v", err)
	}
	certs := &certHolder{}
	certs.set(oldCert)

	if err := renewCert(upstream.Client(), certs, cfg); err != nil {
		t.Fatalf("renewCert() lỗi: %v", err)
	}

	gotCert, err := certs.get(nil)
	if err != nil {
		t.Fatalf("certs.get() lỗi sau renew: %v", err)
	}
	wantCert, err := tls.X509KeyPair([]byte(newCertPEM), []byte(newKeyPEM))
	if err != nil {
		t.Fatalf("dựng lại new cert test để so sánh thất bại: %v", err)
	}
	if string(gotCert.Certificate[0]) != string(wantCert.Certificate[0]) {
		t.Fatalf("certHolder không được hot-swap sang cert MỚI sau renewCert thành công")
	}

	gotCertBytes, _ := os.ReadFile(cfg.certPath())
	if string(gotCertBytes) != newCertPEM {
		t.Fatalf("agent.crt trên đĩa không phải cert MỚI đã renew")
	}
	gotKeyBytes, _ := os.ReadFile(cfg.keyPath())
	if string(gotKeyBytes) != newKeyPEM {
		t.Fatalf("agent.key trên đĩa không phải key MỚI đã renew")
	}
	gotRootBytes, _ := os.ReadFile(cfg.rootPath())
	if string(gotRootBytes) != newRootPEM {
		t.Fatalf("ca-root.crt trên đĩa không phải root MỚI đã renew")
	}

	for _, p := range []string{cfg.certPath() + ".tmp", cfg.keyPath() + ".tmp", cfg.rootPath() + ".tmp"} {
		if fileExists(p) {
			t.Fatalf("file tạm %s vẫn còn sau renewCert thành công — writeFileAtomic phải dọn qua os.Rename", p)
		}
	}
}

// TestRenewCert_MismatchedKeyPairDoesNotTouchExistingCertOrFiles kiểm tra
// pattern validate-trước-khi-commit: renewCert phải gọi tls.X509KeyPair để
// xác thực cert/key nhận được KHỚP nhau trước khi ghi bất cứ gì xuống đĩa
// hay hot-swap certHolder — 1 phản hồi renew hỏng (vd Orchestrator/step-ca
// có bug) không được phép làm hại cert cũ đang chạy tốt.
func TestRenewCert_MismatchedKeyPairDoesNotTouchExistingCertOrFiles(t *testing.T) {
	oldCertPEM, oldKeyPEM := generateTestCertPEM(t, "agent-old", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	unrelatedCertPEM, _ := generateTestCertPEM(t, "unrelated", time.Now(), time.Now().Add(time.Hour))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// key_pem của 1 cặp cert HOÀN TOÀN khác với cert_pem — tls.X509KeyPair
		// phải từ chối cặp lệch này.
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem":    unrelatedCertPEM,
			"key_pem":     oldKeyPEM,
			"ca_root_pem": "NEW-ROOT",
		})
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := config{managerURL: upstream.URL, hostname: "agent-test-host", stateDir: dir}
	os.WriteFile(cfg.certPath(), []byte(oldCertPEM), 0600)
	os.WriteFile(cfg.keyPath(), []byte(oldKeyPEM), 0600)
	os.WriteFile(cfg.rootPath(), []byte("OLD-ROOT"), 0600)

	oldCert, err := tls.X509KeyPair([]byte(oldCertPEM), []byte(oldKeyPEM))
	if err != nil {
		t.Fatalf("dựng old cert test thất bại: %v", err)
	}
	certs := &certHolder{}
	certs.set(oldCert)

	if err := renewCert(upstream.Client(), certs, cfg); err == nil {
		t.Fatalf("renewCert() không lỗi dù cert/key nhận được không khớp nhau")
	}

	gotCert, err := certs.get(nil)
	if err != nil {
		t.Fatalf("certs.get() lỗi: %v", err)
	}
	if string(gotCert.Certificate[0]) != string(oldCert.Certificate[0]) {
		t.Fatalf("certHolder bị thay đổi dù renewCert thất bại — vi phạm validate-trước-khi-commit")
	}

	wantFiles := map[string]string{
		cfg.certPath(): oldCertPEM,
		cfg.keyPath():  oldKeyPEM,
		cfg.rootPath(): "OLD-ROOT",
	}
	for path, want := range wantFiles {
		got, _ := os.ReadFile(path)
		if string(got) != want {
			t.Fatalf("file %s bị ghi đè dù renewCert thất bại (validate-trước-khi-commit phải chặn ghi đĩa): got=%q want=%q", path, got, want)
		}
	}
}

func TestRenewCert_NonOKStatusDoesNotTouchExistingCertOrCreateFiles(t *testing.T) {
	oldCertPEM, oldKeyPEM := generateTestCertPEM(t, "agent-old", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"detail":"renew cert cho host đang bị khoá (agent_renewal_blocked=true)"}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := config{managerURL: upstream.URL, hostname: "agent-test-host", stateDir: dir}
	oldCert, err := tls.X509KeyPair([]byte(oldCertPEM), []byte(oldKeyPEM))
	if err != nil {
		t.Fatalf("dựng old cert test thất bại: %v", err)
	}
	certs := &certHolder{}
	certs.set(oldCert)

	if err := renewCert(upstream.Client(), certs, cfg); err == nil {
		t.Fatalf("renewCert() không lỗi dù Agent Manager trả 403 (renewal bị khoá)")
	}

	gotCert, err := certs.get(nil)
	if err != nil {
		t.Fatalf("certs.get() lỗi: %v", err)
	}
	if string(gotCert.Certificate[0]) != string(oldCert.Certificate[0]) {
		t.Fatalf("certHolder bị thay đổi dù renewCert thất bại với status 403")
	}
	if fileExists(cfg.certPath()) || fileExists(cfg.keyPath()) || fileExists(cfg.rootPath()) {
		t.Fatalf("renewCert tạo file cert/key/root trên đĩa dù chưa nhận được phản hồi hợp lệ (status 403)")
	}
}

func TestRenewCert_MalformedJSONResponseDoesNotTouchExistingCert(t *testing.T) {
	oldCertPEM, oldKeyPEM := generateTestCertPEM(t, "agent-old", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("không phải JSON"))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := config{managerURL: upstream.URL, hostname: "agent-test-host", stateDir: dir}
	oldCert, err := tls.X509KeyPair([]byte(oldCertPEM), []byte(oldKeyPEM))
	if err != nil {
		t.Fatalf("dựng old cert test thất bại: %v", err)
	}
	certs := &certHolder{}
	certs.set(oldCert)

	if err := renewCert(upstream.Client(), certs, cfg); err == nil {
		t.Fatalf("renewCert() không lỗi dù phản hồi renew không phải JSON hợp lệ")
	}

	gotCert, err := certs.get(nil)
	if err != nil {
		t.Fatalf("certs.get() lỗi: %v", err)
	}
	if string(gotCert.Certificate[0]) != string(oldCert.Certificate[0]) {
		t.Fatalf("certHolder bị thay đổi dù phản hồi renew không phải JSON hợp lệ")
	}
	if fileExists(cfg.certPath()) {
		t.Fatalf("renewCert ghi agent.crt xuống đĩa dù phản hồi JSON hỏng")
	}
}
