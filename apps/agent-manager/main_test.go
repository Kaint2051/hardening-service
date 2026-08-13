package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOrchestrator giả lập Orchestrator thật để test handler mà không cần
// step-ca/Postgres — chỉ kiểm tra agent-manager relay ĐÚNG path + body +
// Authorization header, và trả nguyên status/body ngược lại cho client.
func fakeOrchestrator(t *testing.T, wantPath string, wantSecret string, respStatus int, respBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, muốn %q", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantSecret {
			t.Errorf("Authorization = %q, muốn Bearer %s", got, wantSecret)
		}
		w.WriteHeader(respStatus)
		w.Write([]byte(respBody))
	}))
}

func TestHandleEnroll_MissingFields(t *testing.T) {
	h := handleEnroll("http://unused", "secret")
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"hostname":""}`))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, muốn 400", rec.Code)
	}
}

func TestHandleEnroll_RejectsOversizedBody(t *testing.T) {
	h := handleEnroll("http://unused", "secret")
	// 1 body vượt maxRequestBodyBytes (1 MiB) — client chưa xác thực (không
	// cần client cert cho /enroll) không được phép ép decoder đọc vô hạn.
	oversized := `{"hostname":"h","token":"` + strings.Repeat("A", maxRequestBodyBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, muốn 413 (body vượt giới hạn)", rec.Code)
	}
}

func TestHandleMTLSRelay_RejectsOversizedBody(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/scan-result", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	oversized := `{"hostname":"h","result_summary":{"pad":"` + strings.Repeat("A", maxRequestBodyBytes+1024) + `"}}`
	req := requestWithClientCN("h", oversized)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, muốn 413 (body vượt giới hạn)", rec.Code)
	}
}

func TestHandleEnroll_RelaysToOrchestrator(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/verify-and-enroll", "shhh", http.StatusOK,
		`{"cert_pem":"C","key_pem":"K","ca_root_pem":"R"}`)
	defer upstream.Close()

	h := handleEnroll(upstream.URL, "shhh")
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"hostname":"h1","token":"tok"}`))
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, muốn 200, body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body không phải JSON hợp lệ: %v", err)
	}
	if out["cert_pem"] != "C" {
		t.Fatalf("cert_pem = %q, muốn C", out["cert_pem"])
	}
}

func TestHandleEnroll_PassesThroughUpstreamError(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/verify-and-enroll", "shhh", http.StatusUnauthorized,
		`{"detail":"token đã được dùng"}`)
	defer upstream.Close()

	h := handleEnroll(upstream.URL, "shhh")
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"hostname":"h1","token":"tok"}`))
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, muốn 401 (pass-through từ Orchestrator)", rec.Code)
	}
}

func requestWithClientCN(cn, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", strings.NewReader(body))
	if cn == "" {
		return req
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: cn}},
		},
	}
	return req
}

func TestHandleHeartbeat_RejectsMissingClientCert(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/heartbeat", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("", `{"hostname":"h1"}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, muốn 401", rec.Code)
	}
}

func TestHandleHeartbeat_RejectsHostnameMismatch(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/heartbeat", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-B"}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, muốn 403 (CN != hostname khai báo)", rec.Code)
	}
}

func TestHandleHeartbeat_SuccessRelaysToOrchestrator(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/heartbeat", "shhh", http.StatusNoContent, "")
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/heartbeat", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-A"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, muốn 204, body=%s", rec.Code, rec.Body.String())
	}
}

func TestWaitForServerCert_SucceedsAfterTransientFailures(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedPEM(t)
	var attempts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			// Mô phỏng chính xác lỗi thật quan sát được lúc deploy: Orchestrator
			// container đã start nhưng chưa chạy xong alembic migrate + uvicorn.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp := certResponse{CertPEM: certPEM, KeyPEM: keyPEM, CARootPEM: certPEM}
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	ident := &serverIdentity{}
	err := waitForServerCert(ident, upstream.URL, "secret", 10*time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("waitForServerCert lỗi dù Orchestrator sẵn sàng ở lần thử thứ 3: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("số lần thử = %d, muốn 3", attempts.Load())
	}
}

func TestWaitForServerCert_GivesUpAfterDeadline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	ident := &serverIdentity{}
	err := waitForServerCert(ident, upstream.URL, "secret", 5*time.Millisecond, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("waitForServerCert không lỗi dù Orchestrator luôn 503 (phải bỏ cuộc sau deadline)")
	}
}

func generateSelfSignedPEM(t *testing.T) (certPEM string, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("sinh key test thất bại: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-manager"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"agent-manager"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tạo cert test thất bại: %v", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key test thất bại: %v", err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certOut), string(keyOut)
}

func TestHandleHeartbeat_CaseInsensitiveHostnameMatch(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/heartbeat", "shhh", http.StatusNoContent, "")
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/heartbeat", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("Host-A.Internal", `{"hostname":"host-a.internal"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, muốn 204 (so khớp hostname không phân biệt hoa/thường)", rec.Code)
	}
}

// TestHandleMTLSRelay_RelaysAuthenticatedCNNotClientSuppliedCasing chứng minh
// vá lỗ hổng thật (rà soát đối kháng): body["hostname"] relay tới Orchestrator
// PHẢI là CN đã xác thực bằng cert, KHÔNG phải chuỗi hostname (case tuỳ chọn)
// client tự gõ trong body — nếu không, 1 agent hợp lệ có thể tự khai hostname
// khác case của host mình để claim/report job của host KHÁC (Orchestrator so
// khớp Job.hostname case-sensitive).
func TestHandleMTLSRelay_RelaysAuthenticatedCNNotClientSuppliedCasing(t *testing.T) {
	var gotBody map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body relay tới upstream thất bại: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/heartbeat", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	// CN case gốc "Host-A.Internal", client tự khai case KHÁC "host-a.internal"
	// trong body — EqualFold cho qua, nhưng body relay đi PHẢI dùng đúng CN.
	req := requestWithClientCN("Host-A.Internal", `{"hostname":"host-a.internal"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, muốn 204", rec.Code)
	}
	if gotBody["hostname"] != "Host-A.Internal" {
		t.Fatalf(
			"hostname relay tới Orchestrator = %q, muốn đúng CN đã xác thực %q (không phải chuỗi client tự khai)",
			gotBody["hostname"], "Host-A.Internal",
		)
	}
}

func TestHandleMTLSRelay_ScanResultRelaysNestedSummary(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/scan-result", "shhh", http.StatusCreated,
		`{"job_id":42}`)
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/scan-result", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-A","scap_profile":"p1","result_summary":{"scan_result_pass":"10","findings":[{"rule_id":"r1"}]}}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, muốn 201, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMTLSRelay_FimEventRelays(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/fim-event", "shhh", http.StatusCreated, `{"id":1}`)
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/fim-event", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-A","path":"/etc/passwd","event_type":"modified","old_hash":"aa","new_hash":"bb"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, muốn 201, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMTLSRelay_RejectsInvalidJSON(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/heartbeat", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, muốn 400", rec.Code)
	}
}

// unlimitedLimiter dùng cho mọi test KHÔNG liên quan tới rate limit — burst
// đủ lớn để không bao giờ chạm ngưỡng trong 1 lần chạy test.
func unlimitedLimiter() *rateLimiter {
	return newRateLimiter(1e6, 1e6)
}

func TestRateLimiter_AllowsUpToBurstThenBlocks(t *testing.T) {
	rl := newRateLimiter(0, 3) // rate=0: không nạp lại trong lúc test, chỉ test đúng sức chứa burst
	for i := 0; i < 3; i++ {
		if !rl.allow("host-a") {
			t.Fatalf("request thứ %d trong burst bị chặn, lẽ ra phải cho qua", i+1)
		}
	}
	if rl.allow("host-a") {
		t.Fatalf("request vượt burst vẫn được cho qua")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	rl := newRateLimiter(1000, 1) // rate rất cao để refill gần như ngay, test không phải chờ lâu
	if !rl.allow("host-a") {
		t.Fatalf("request đầu tiên bị chặn")
	}
	if rl.allow("host-a") {
		t.Fatalf("request thứ 2 ngay sau đó (chưa kịp refill) vẫn được cho qua")
	}
	time.Sleep(20 * time.Millisecond) // đủ để nạp lại >= 1 token ở rate=1000/s
	if !rl.allow("host-a") {
		t.Fatalf("request sau khi đợi refill vẫn bị chặn")
	}
}

func TestRateLimiter_IsPerKeyNotGlobal(t *testing.T) {
	rl := newRateLimiter(0, 1)
	if !rl.allow("host-a") {
		t.Fatalf("host-a lần đầu bị chặn")
	}
	if !rl.allow("host-b") {
		t.Fatalf("host-b bị ảnh hưởng bởi budget đã dùng của host-a — rate limit phải tách riêng theo key")
	}
}

func TestHandleMTLSRelay_RateLimitsPerHostname(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/heartbeat", "shhh", http.StatusNoContent, "")
	defer upstream.Close()

	limiter := newRateLimiter(0, 1)
	h := handleMTLSRelay(upstream.URL+"/internal/agent/heartbeat", "shhh", limiter, maxRequestBodyBytes)

	req1 := requestWithClientCN("host-A", `{"hostname":"host-A"}`)
	rec1 := httptest.NewRecorder()
	h(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("request đầu: status = %d, muốn 204", rec1.Code)
	}

	req2 := requestWithClientCN("host-A", `{"hostname":"host-A"}`)
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("request thứ 2 dồn dập: status = %d, muốn 429", rec2.Code)
	}
}

// ---- metrics / GET /metrics ----

func TestMetrics_RecordAndSnapshot(t *testing.T) {
	m := newMetrics()
	m.recordRelay("heartbeat", 204)
	m.recordRelay("heartbeat", 204)
	m.recordRelay("heartbeat", 429)
	m.recordRelay("enroll", 200)

	snap := m.snapshot()
	if snap["heartbeat"][204] != 2 {
		t.Fatalf("heartbeat/204 = %d, muốn 2", snap["heartbeat"][204])
	}
	if snap["heartbeat"][429] != 1 {
		t.Fatalf("heartbeat/429 = %d, muốn 1", snap["heartbeat"][429])
	}
	if snap["enroll"][200] != 1 {
		t.Fatalf("enroll/200 = %d, muốn 1", snap["enroll"][200])
	}
}

func TestMetricsMiddleware_RecordsStatusFromWrappedHandler(t *testing.T) {
	m := newMetrics()
	inner := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"nope"}`, http.StatusForbidden)
	}
	h := metricsMiddleware("heartbeat", m, inner)

	req := httptest.NewRequest(http.MethodPost, "/heartbeat", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("middleware phải KHÔNG đổi status trả về client, có = %d", rec.Code)
	}
	snap := m.snapshot()
	if snap["heartbeat"][http.StatusForbidden] != 1 {
		t.Fatalf("metrics không đếm đúng status 403 từ handler bên trong: %+v", snap)
	}
}

func TestMetricsMiddleware_RealEndpointRecordsSuccessAndRateLimit(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/heartbeat", "shhh", http.StatusNoContent, "")
	defer upstream.Close()

	m := newMetrics()
	limiter := newRateLimiter(0, 1)
	h := metricsMiddleware("heartbeat", m, handleMTLSRelay(upstream.URL+"/internal/agent/heartbeat", "shhh", limiter, maxRequestBodyBytes))

	h(httptest.NewRecorder(), requestWithClientCN("host-A", `{"hostname":"host-A"}`))
	h(httptest.NewRecorder(), requestWithClientCN("host-A", `{"hostname":"host-A"}`)) // vượt burst=1 -> 429

	snap := m.snapshot()
	if snap["heartbeat"][http.StatusNoContent] != 1 {
		t.Fatalf("thiếu đếm request thành công: %+v", snap)
	}
	if snap["heartbeat"][http.StatusTooManyRequests] != 1 {
		t.Fatalf("thiếu đếm request bị rate-limit: %+v", snap)
	}
}

func TestRateLimiter_HostCount(t *testing.T) {
	rl := newRateLimiter(1e6, 1e6)
	if rl.hostCount() != 0 {
		t.Fatalf("hostCount ban đầu = %d, muốn 0", rl.hostCount())
	}
	rl.allow("host-a")
	rl.allow("host-b")
	rl.allow("host-a") // gọi lại host cũ không tăng thêm hostCount
	if rl.hostCount() != 2 {
		t.Fatalf("hostCount = %d, muốn 2 (host-a, host-b)", rl.hostCount())
	}
}

func TestServerIdentity_RenewalStatusReflectsLastAttempt(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedPEM(t)
	ident := &serverIdentity{}

	if success, at := ident.renewalStatus(); success || !at.IsZero() {
		t.Fatalf("trạng thái ban đầu phải là chưa renew lần nào, có success=%v at=%v", success, at)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	ident.refresh(failing.URL, "secret")
	failing.Close()
	if success, at := ident.renewalStatus(); success || at.IsZero() {
		t.Fatalf("sau lần refresh lỗi: success=%v (muốn false), at rỗng=%v (muốn false)", success, at.IsZero())
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := certResponse{CertPEM: certPEM, KeyPEM: keyPEM, CARootPEM: certPEM}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ok.Close()
	if err := ident.refresh(ok.URL, "secret"); err != nil {
		t.Fatalf("refresh lẽ ra phải thành công: %v", err)
	}
	if success, at := ident.renewalStatus(); !success || at.IsZero() {
		t.Fatalf("sau lần refresh thành công: success=%v (muốn true), at rỗng=%v (muốn false)", success, at.IsZero())
	}
}

func TestHandleMetrics_ExposesPrometheusTextFormat(t *testing.T) {
	m := newMetrics()
	m.recordRelay("heartbeat", 204)
	m.recordRelay("heartbeat", 429)
	limiter := newRateLimiter(1e6, 1e6)
	limiter.allow("host-a")
	limiter.allow("host-b")
	ident := &serverIdentity{}
	certPEM, keyPEM := generateSelfSignedPEM(t)
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := certResponse{CertPEM: certPEM, KeyPEM: keyPEM, CARootPEM: certPEM}
		json.NewEncoder(w).Encode(resp)
	}))
	defer okServer.Close()
	if err := ident.refresh(okServer.URL, "secret"); err != nil {
		t.Fatalf("chuẩn bị ident thất bại: %v", err)
	}

	h := handleMetrics(m, limiter, ident)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, muốn 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `agent_manager_relay_requests_total{endpoint="heartbeat",status="204"} 1`) {
		t.Fatalf("thiếu counter heartbeat/204 đúng định dạng, body:\n%s", body)
	}
	if !strings.Contains(body, `agent_manager_relay_requests_total{endpoint="heartbeat",status="429"} 1`) {
		t.Fatalf("thiếu counter heartbeat/429 đúng định dạng, body:\n%s", body)
	}
	if !strings.Contains(body, "agent_manager_known_hosts 2") {
		t.Fatalf("thiếu gauge known_hosts đúng giá trị, body:\n%s", body)
	}
	if !strings.Contains(body, "agent_manager_server_cert_renewal_success 1") {
		t.Fatalf("thiếu gauge renewal_success đúng giá trị, body:\n%s", body)
	}
	if !strings.Contains(body, "agent_manager_server_cert_renewal_timestamp_seconds ") {
		t.Fatalf("thiếu gauge renewal_timestamp, body:\n%s", body)
	}
}

func TestHandleMTLSRelay_RateLimitDoesNotAffectOtherHostnames(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/heartbeat", "shhh", http.StatusNoContent, "")
	defer upstream.Close()

	limiter := newRateLimiter(0, 1)
	h := handleMTLSRelay(upstream.URL+"/internal/agent/heartbeat", "shhh", limiter, maxRequestBodyBytes)

	h(httptest.NewRecorder(), requestWithClientCN("host-A", `{"hostname":"host-A"}`))
	// host-A đã dùng hết budget ở trên — host-B vẫn phải được cho qua bình
	// thường, chứng minh giới hạn tách theo hostname, không phải toàn cục.
	rec := httptest.NewRecorder()
	h(rec, requestWithClientCN("host-B", `{"hostname":"host-B"}`))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("host-B: status = %d, muốn 204 (không bị ảnh hưởng bởi host-A)", rec.Code)
	}
}

// ---- Active Response: /remediate-jobs/claim, /remediation-bundle, /remediate-result ----
//
// Cả 3 route đều dùng chung handleMTLSRelay (xem main()), nên các test dưới
// đây chủ yếu xác nhận ĐÚNG orchestratorPath được relay tới + hành vi
// maxBytes tham số hoá đúng theo route (1 MiB cho 2 route đầu, 4 MiB riêng
// cho remediate-result) — không lặp lại toàn bộ ma trận test của
// handleMTLSRelay (đã cover ở heartbeat/scan-result/fim-event phía trên).

func TestHandleRemediateJobsClaim_RejectsMissingClientCert(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/remediate-jobs/claim", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("", `{"hostname":"h1"}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, muốn 401", rec.Code)
	}
}

func TestHandleRemediateJobsClaim_RejectsHostnameMismatch(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/remediate-jobs/claim", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-B"}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, muốn 403 (CN != hostname khai báo)", rec.Code)
	}
}

func TestHandleRemediateJobsClaim_SuccessRelaysToOrchestrator(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/remediate-jobs/claim", "shhh", http.StatusOK,
		`{"job_id":1,"control_id":"c1","remediation_ref":"r1","dry_run":true}`)
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/remediate-jobs/claim", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-A"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, muốn 200, body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body không phải JSON hợp lệ: %v", err)
	}
	if out["remediation_ref"] != "r1" {
		t.Fatalf("remediation_ref = %v, muốn r1", out["remediation_ref"])
	}
}

func TestHandleRemediateJobsClaim_RejectsOversizedBody(t *testing.T) {
	// maxBytes = maxRequestBodyBytes (1 MiB, không đổi so với các route JSON
	// nhỏ khác) — tham số hoá handleMTLSRelay KHÔNG được nới lỏng giới hạn
	// này cho route claim (request nhỏ, không có lý do cần hơn 1 MiB).
	h := handleMTLSRelay("http://unused/internal/agent/remediate-jobs/claim", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	oversized := `{"hostname":"` + strings.Repeat("A", maxRequestBodyBytes+1024) + `"}`
	req := requestWithClientCN("h", oversized)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, muốn 413 (body vượt giới hạn 1 MiB)", rec.Code)
	}
}

func TestHandleRemediationBundle_RejectsMissingClientCert(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/remediation-bundle", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("", `{"hostname":"h1","remediation_ref":"r1"}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, muốn 401", rec.Code)
	}
}

func TestHandleRemediationBundle_SuccessRelaysToOrchestrator(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/remediation-bundle", "shhh", http.StatusOK,
		`{"remediation_ref":"r1","content_tar_gz_b64":"AA==","signature_asc_b64":"BB=="}`)
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/remediation-bundle", "shhh", unlimitedLimiter(), maxRequestBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-A","remediation_ref":"r1"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, muốn 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleRemediationBundle_RejectsOversizedBody(t *testing.T) {
	// Request vào route này nhỏ (hostname + remediation_ref) — chính response
	// (bundle lớn) mới đi qua chiều relayJSON không giới hạn, nên chiều
	// REQUEST vẫn phải giữ nguyên trần 1 MiB như trước khi tham số hoá.
	h := handleMTLSRelay("http://unused/internal/agent/remediation-bundle", "secret", unlimitedLimiter(), maxRequestBodyBytes)
	oversized := `{"hostname":"h","remediation_ref":"` + strings.Repeat("A", maxRequestBodyBytes+1024) + `"}`
	req := requestWithClientCN("h", oversized)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, muốn 413 (body vượt giới hạn 1 MiB)", rec.Code)
	}
}

func TestHandleRemediateResult_RejectsMissingClientCert(t *testing.T) {
	h := handleMTLSRelay("http://unused/internal/agent/remediate-result", "secret", unlimitedLimiter(), maxRemediateResultBodyBytes)
	req := requestWithClientCN("", `{"hostname":"h1","job_id":1,"exit_code":0}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, muốn 401", rec.Code)
	}
}

func TestHandleRemediateResult_SuccessRelaysToOrchestrator(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/remediate-result", "shhh", http.StatusOK, `{}`)
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/remediate-result", "shhh", unlimitedLimiter(), maxRemediateResultBodyBytes)
	req := requestWithClientCN("host-A", `{"hostname":"host-A","job_id":1,"exit_code":0,"dry_run":false,"log_tail":"ok"}`)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, muốn 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleRemediateResult_AcceptsLargeBodyUnderNewLimit là test hồi quy
// QUAN TRỌNG nhất của lần tham số hoá này: chứng minh route /remediate-result
// KHÔNG bị chặn ở bước đọc body (MaxBytesReader) với payload cỡ backup 2 MiB
// sau base64-encode (~2.7 MiB) + overhead JSON — tức maxRemediateResultBodyBytes
// (4 MiB) thật sự có hiệu lực cho route này, khác với maxRequestBodyBytes (1
// MiB) vẫn áp dụng cho các route khác. Không cần Orchestrator thật xử lý
// đúng nghiệp vụ — fakeOrchestrator chỉ cần nhận được request trọn vẹn và trả
// 200 là đủ chứng minh không bị chặn ở tầng agent-manager.
func TestHandleRemediateResult_AcceptsLargeBodyUnderNewLimit(t *testing.T) {
	upstream := fakeOrchestrator(t, "/internal/agent/remediate-result", "shhh", http.StatusOK, `{}`)
	defer upstream.Close()

	h := handleMTLSRelay(upstream.URL+"/internal/agent/remediate-result", "shhh", unlimitedLimiter(), maxRemediateResultBodyBytes)
	// ~3 MiB base64 payload trong backup_tar_b64 — vượt xa maxRequestBodyBytes
	// (1 MiB) cũ nhưng vẫn dưới maxRemediateResultBodyBytes (4 MiB) mới.
	backupPayload := strings.Repeat("A", 3*1024*1024)
	body := `{"hostname":"host-A","job_id":1,"exit_code":0,"dry_run":false,"log_tail":"ok","backup_tar_b64":"` + backupPayload + `"}`
	req := requestWithClientCN("host-A", body)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, muốn 200 (body ~3 MiB phải lọt qua MaxBytesReader 4 MiB), body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMTLSRelay_RemediateResult_StillRejectsBodyOverNewLimit(t *testing.T) {
	// Đối xứng với test trên: body VƯỢT maxRemediateResultBodyBytes (4 MiB)
	// vẫn phải bị 413 — tham số hoá không có nghĩa là bỏ giới hạn hoàn toàn
	// cho route này, chỉ là nâng trần lên mức phù hợp.
	h := handleMTLSRelay("http://unused/internal/agent/remediate-result", "secret", unlimitedLimiter(), maxRemediateResultBodyBytes)
	oversized := `{"hostname":"h","job_id":1,"exit_code":0,"backup_tar_b64":"` + strings.Repeat("A", int(maxRemediateResultBodyBytes)+1024) + `"}`
	req := requestWithClientCN("h", oversized)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, muốn 413 (body vượt giới hạn 4 MiB)", rec.Code)
	}
}

func TestHandleMTLSRelayWithTimeout_RespectsGivenTimeout(t *testing.T) {
	// Trước đây relayJSON hardcode 15s cho MỌI route, kể cả /remediation-
	// bundle (có thể mang bundle content lớn hơn nhiều JSON nhỏ khác) — khiến
	// chính relay này thành ràng buộc chặt nhất, chặt hơn cả Reporter phía
	// gọi đã tự cho phép 30s. Test bằng timeout GIẢ nhỏ (không phải 15s/30s
	// thật, quá chậm cho unit test) để xác nhận tham số timeout thật sự có
	// tác dụng, không phải chỉ đổi tên biến mà giá trị vẫn hardcode ở đâu đó.
	const upstreamDelay = 60 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(upstreamDelay)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	shortTimeoutHandler := handleMTLSRelayWithTimeout(
		upstream.URL+"/internal/agent/remediation-bundle", "shhh", unlimitedLimiter(), maxRequestBodyBytes,
		upstreamDelay/3,
	)
	rec := httptest.NewRecorder()
	shortTimeoutHandler(rec, requestWithClientCN("host-A", `{"hostname":"host-A"}`))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("timeout ngắn hơn độ trễ upstream: status = %d, muốn 502 (phải bỏ cuộc đúng lúc)", rec.Code)
	}

	longTimeoutHandler := handleMTLSRelayWithTimeout(
		upstream.URL+"/internal/agent/remediation-bundle", "shhh", unlimitedLimiter(), maxRequestBodyBytes,
		upstreamDelay*10,
	)
	rec2 := httptest.NewRecorder()
	longTimeoutHandler(rec2, requestWithClientCN("host-A", `{"hostname":"host-A"}`))
	if rec2.Code != http.StatusOK {
		t.Fatalf("timeout dài hơn độ trễ upstream: status = %d, muốn 200 (không được bỏ cuộc sớm)", rec2.Code)
	}
}
