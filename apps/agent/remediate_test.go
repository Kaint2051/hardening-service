package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// startExecutorTestDouble dựng 1 Unix socket test double đóng vai Executor —
// mỗi kết nối: đọc đúng 1 jobEnvelope, gọi respond() để lấy executionResult
// giả lập. Nếu respond trả shouldRespond=false, test double đóng kết nối mà
// KHÔNG ghi gì cả, mô phỏng Executor treo/chết — executeViaExecutor phải
// thấy lỗi (EOF) ngay lập tức thay vì phải chờ đủ executorIOTimeout thật (vài
// phút), để test chạy nhanh.
func startExecutorTestDouble(t *testing.T, respond func(jobEnvelope) (executionResult, bool)) (socketPath string, getEnvelopes func() []jobEnvelope) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "executor.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix test socket thất bại: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var envelopes []jobEnvelope

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var env jobEnvelope
				if err := json.NewDecoder(c).Decode(&env); err != nil {
					return
				}
				mu.Lock()
				envelopes = append(envelopes, env)
				mu.Unlock()

				result, shouldRespond := respond(env)
				if !shouldRespond {
					return
				}
				json.NewEncoder(c).Encode(result)
			}(conn)
		}
	}()

	return sockPath, func() []jobEnvelope {
		mu.Lock()
		defer mu.Unlock()
		return append([]jobEnvelope{}, envelopes...)
	}
}

// remediateTestServer dựng 1 httptest.Server đóng vai Agent Manager (relay
// mTLS-terminated), đếm số lần gọi từng route + cho phép test cắm handler
// riêng cho 3 route mới (claim/bundle/result) — mirror style
// fimEventRecorder ở fim_test.go.
type remediateTestServer struct {
	srv *httptest.Server

	mu            sync.Mutex
	claimCalls    int
	bundleCalls   int
	resultCalls   int
	lastBundleReq map[string]string
	lastResultReq map[string]any
	claimHandler  func(w http.ResponseWriter, r *http.Request)
	bundleHandler func(w http.ResponseWriter, r *http.Request)
	resultHandler func(w http.ResponseWriter, r *http.Request)
}

func newRemediateTestServer(t *testing.T) *remediateTestServer {
	t.Helper()
	rts := &remediateTestServer{}
	rts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/remediate-jobs/claim":
			rts.mu.Lock()
			rts.claimCalls++
			rts.mu.Unlock()
			if rts.claimHandler != nil {
				rts.claimHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/remediation-bundle":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			rts.mu.Lock()
			rts.bundleCalls++
			rts.lastBundleReq = body
			rts.mu.Unlock()
			if rts.bundleHandler != nil {
				rts.bundleHandler(w, r)
				return
			}
			t.Errorf("bundleHandler không được cấu hình nhưng /remediation-bundle bị gọi")
			w.WriteHeader(http.StatusInternalServerError)
		case "/remediate-result":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			rts.mu.Lock()
			rts.resultCalls++
			rts.lastResultReq = body
			rts.mu.Unlock()
			if rts.resultHandler != nil {
				rts.resultHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		default:
			t.Errorf("route không mong đợi bị gọi: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(rts.srv.Close)
	return rts
}

func (rts *remediateTestServer) snapshot() (claimCalls, bundleCalls, resultCalls int) {
	rts.mu.Lock()
	defer rts.mu.Unlock()
	return rts.claimCalls, rts.bundleCalls, rts.resultCalls
}

func TestPollAndExecuteRemediation_NoJobDoesNotCallBundleOrResult(t *testing.T) {
	rts := newRemediateTestServer(t) // claim mặc định trả 204

	cfg := config{
		managerURL:            rts.srv.URL,
		hostname:              "h1",
		contentCacheDir:       t.TempDir(),
		executorSocketPath:    filepath.Join(t.TempDir(), "khong-ton-tai.sock"),
		remediatePollInterval: time.Second,
	}

	pollAndExecuteRemediation(rts.srv.Client(), cfg)

	claimCalls, bundleCalls, resultCalls := rts.snapshot()
	if claimCalls != 1 {
		t.Fatalf("claimCalls = %d, muốn đúng 1 lần gọi claim", claimCalls)
	}
	if bundleCalls != 0 || resultCalls != 0 {
		t.Fatalf("không có job (204) nhưng vẫn gọi bundle=%d result=%d — phải bằng 0 cả 2", bundleCalls, resultCalls)
	}
}

// TestPollAndExecuteRemediation_NotExecutedReportsFailure
// chứng minh vá lỗi thật (rà soát đối kháng): Executor trả Verified=true
// nhưng Executed=false (lỗi hạ tầng SAU KHI verify chữ ký OK — vd giải nén
// bundle lỗi, thiếu playbook.yml) PHẢI được báo về Orchestrator như 1 lỗi
// (exit_code != 0, có field "error"), KHÔNG PHẢI exit_code=0 mặc định
// (zero-value Go của executionResult.ExitCode khi Executed=false) — nếu
// không, Orchestrator sẽ đánh dấu job "succeeded" dù thực chất không có gì
// thực thi trên host, tạo trạng thái compliance SAI.
func TestPollAndExecuteRemediation_NotExecutedReportsFailure(t *testing.T) {
	rts := newRemediateTestServer(t)
	rts.claimHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claimResponse{
			JobID: 7, ControlID: "CIS-1.1.1", RemediationRef: "bundle-broken-20260101", DryRun: true,
		})
	}
	rts.bundleHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bundleResponse{
			RemediationRef:  "bundle-broken-20260101",
			ContentTarGzB64: base64.StdEncoding.EncodeToString([]byte("nội dung tar giả")),
			SignatureAscB64: base64.StdEncoding.EncodeToString([]byte("chữ ký giả")),
		})
	}

	sockPath, _ := startExecutorTestDouble(t, func(env jobEnvelope) (executionResult, bool) {
		// Verified=true (chữ ký hợp lệ) nhưng Executed=false (vd giải nén
		// bundle thất bại) — ExitCode giữ zero-value 0, đúng hành vi thật
		// của executeRemediation khi Executed=false (xem execute.go).
		return executionResult{
			Verified: true, SignerFingerprint: "ABCDEF0123456789",
			Executed: false, Reason: "giải nén bundle thất bại: không có playbook.yml",
		}, true
	})

	cfg := config{
		managerURL:         rts.srv.URL,
		hostname:           "h1",
		contentCacheDir:    t.TempDir(),
		executorSocketPath: sockPath,
	}

	pollAndExecuteRemediation(rts.srv.Client(), cfg)

	rts.mu.Lock()
	gotResultReq := rts.lastResultReq
	rts.mu.Unlock()

	if gotResultReq["exit_code"] == float64(0) {
		t.Fatalf(
			"remediate-result exit_code = 0 (\"succeeded\") dù Executor KHÔNG thực thi gì (Executed=false) — "+
				"báo compliance SAI, request đầy đủ: %+v", gotResultReq,
		)
	}
	errMsg, hasError := gotResultReq["error"]
	if !hasError || errMsg == "" {
		t.Fatalf("remediate-result thiếu field \"error\" giải thích lý do không thực thi được: %+v", gotResultReq)
	}
}

func TestPollAndExecuteRemediation_JobExecutesAndReportsResult(t *testing.T) {
	rts := newRemediateTestServer(t)
	rts.claimHandler = func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["hostname"] != "h1" {
			t.Errorf("claim request hostname = %q, muốn h1", body["hostname"])
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claimResponse{
			JobID:          42,
			ControlID:      "CIS-1.1.1",
			RemediationRef: "bundle-xyz-20260101",
			DryRun:         true,
		})
	}
	rts.bundleHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bundleResponse{
			RemediationRef:  "bundle-xyz-20260101",
			ContentTarGzB64: base64.StdEncoding.EncodeToString([]byte("nội dung tar giả")),
			SignatureAscB64: base64.StdEncoding.EncodeToString([]byte("chữ ký giả")),
		})
	}

	wantResult := executionResult{
		Verified:          true,
		SignerFingerprint: "ABCDEF0123456789",
		Executed:          true,
		ExitCode:          0,
		DiffOutput:        "--- a\n+++ b\n",
		BackupTarB64:      base64.StdEncoding.EncodeToString([]byte("backup tar giả")),
		LogTail:           "remediation OK\n",
	}
	sockPath, getEnvelopes := startExecutorTestDouble(t, func(env jobEnvelope) (executionResult, bool) {
		return wantResult, true
	})

	cacheDir := t.TempDir()
	cfg := config{
		managerURL:         rts.srv.URL,
		hostname:           "h1",
		contentCacheDir:    cacheDir,
		executorSocketPath: sockPath,
	}

	pollAndExecuteRemediation(rts.srv.Client(), cfg)

	claimCalls, bundleCalls, resultCalls := rts.snapshot()
	if claimCalls != 1 || bundleCalls != 1 || resultCalls != 1 {
		t.Fatalf("số lần gọi claim=%d bundle=%d result=%d, muốn đúng 1 lần mỗi route", claimCalls, bundleCalls, resultCalls)
	}

	envelopes := getEnvelopes()
	if len(envelopes) != 1 {
		t.Fatalf("Executor nhận %d envelope, muốn đúng 1", len(envelopes))
	}
	gotEnv := envelopes[0]
	if gotEnv.ControlID != "CIS-1.1.1" || gotEnv.RemediationRef != "bundle-xyz-20260101" || !gotEnv.DryRun {
		t.Fatalf("envelope gửi Executor = %+v, không khớp job đã claim", gotEnv)
	}

	rts.mu.Lock()
	gotResultReq := rts.lastResultReq
	rts.mu.Unlock()
	if gotResultReq["hostname"] != "h1" {
		t.Errorf("remediate-result hostname = %v, muốn h1", gotResultReq["hostname"])
	}
	if gotResultReq["job_id"] != float64(42) {
		t.Errorf("remediate-result job_id = %v, muốn 42", gotResultReq["job_id"])
	}
	if gotResultReq["dry_run"] != true {
		t.Errorf("remediate-result dry_run = %v, muốn true (lấy từ job đã claim)", gotResultReq["dry_run"])
	}
	if gotResultReq["exit_code"] != float64(0) {
		t.Errorf("remediate-result exit_code = %v, muốn 0", gotResultReq["exit_code"])
	}
	if gotResultReq["diff_output"] != wantResult.DiffOutput {
		t.Errorf("remediate-result diff_output = %v, muốn %q", gotResultReq["diff_output"], wantResult.DiffOutput)
	}
	if gotResultReq["backup_tar_b64"] != wantResult.BackupTarB64 {
		t.Errorf("remediate-result backup_tar_b64 không khớp executionResult")
	}
	if gotResultReq["log_tail"] != wantResult.LogTail {
		t.Errorf("remediate-result log_tail = %v, muốn %q", gotResultReq["log_tail"], wantResult.LogTail)
	}
	if _, hasError := gotResultReq["error"]; hasError {
		t.Errorf("remediate-result có field error dù thực thi thành công: %v", gotResultReq["error"])
	}

	// Bundle phải được cache đúng layout <dir>/<ref>/content.tar.gz(.sig).
	tarBytes, err := os.ReadFile(filepath.Join(cacheDir, "bundle-xyz-20260101", "content.tar.gz"))
	if err != nil || string(tarBytes) != "nội dung tar giả" {
		t.Fatalf("cache content.tar.gz sai: err=%v got=%q", err, tarBytes)
	}
	sigBytes, err := os.ReadFile(filepath.Join(cacheDir, "bundle-xyz-20260101", "content.tar.gz.sig"))
	if err != nil || string(sigBytes) != "chữ ký giả" {
		t.Fatalf("cache content.tar.gz.sig sai: err=%v got=%q", err, sigBytes)
	}
}

func TestEnsureBundleCached_SecondCallForSameRefSkipsNetwork(t *testing.T) {
	rts := newRemediateTestServer(t)
	rts.bundleHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bundleResponse{
			RemediationRef:  "ref-1",
			ContentTarGzB64: base64.StdEncoding.EncodeToString([]byte("tar-data")),
			SignatureAscB64: base64.StdEncoding.EncodeToString([]byte("sig-data")),
		})
	}

	cfg := config{managerURL: rts.srv.URL, hostname: "h1", contentCacheDir: t.TempDir()}

	if err := ensureBundleCached(rts.srv.Client(), cfg, "ref-1"); err != nil {
		t.Fatalf("ensureBundleCached() lần 1 lỗi: %v", err)
	}
	if err := ensureBundleCached(rts.srv.Client(), cfg, "ref-1"); err != nil {
		t.Fatalf("ensureBundleCached() lần 2 (cache hit) lỗi: %v", err)
	}

	if _, bundleCalls, _ := rts.snapshot(); bundleCalls != 1 {
		t.Fatalf("bundleCalls = %d sau 2 lần gọi cùng ref, muốn đúng 1 (lần 2 phải cache-hit)", bundleCalls)
	}
}

// TestPollAndExecuteRemediation_ExecutorNoResponseStillReportsFailure mô
// phỏng Executor "treo/chết" (đóng kết nối mà không trả executionResult) —
// Reporter PHẢI vẫn POST 1 remediate-result báo lỗi (exit_code khác 0, có
// field error), KHÔNG được để job kẹt "running" vĩnh viễn phía Orchestrator
// chỉ vì Executor không phản hồi.
func TestPollAndExecuteRemediation_ExecutorNoResponseStillReportsFailure(t *testing.T) {
	rts := newRemediateTestServer(t)
	rts.claimHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claimResponse{
			JobID:          7,
			ControlID:      "CIS-2.2.2",
			RemediationRef: "ref-treo",
			DryRun:         false,
		})
	}
	rts.bundleHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bundleResponse{
			RemediationRef:  "ref-treo",
			ContentTarGzB64: base64.StdEncoding.EncodeToString([]byte("tar")),
			SignatureAscB64: base64.StdEncoding.EncodeToString([]byte("sig")),
		})
	}

	// shouldRespond=false — test double đọc envelope rồi đóng kết nối ngay,
	// không ghi gì cả, mô phỏng Executor chết/treo giữa chừng.
	sockPath, _ := startExecutorTestDouble(t, func(env jobEnvelope) (executionResult, bool) {
		return executionResult{}, false
	})

	cfg := config{
		managerURL:         rts.srv.URL,
		hostname:           "h1",
		contentCacheDir:    t.TempDir(),
		executorSocketPath: sockPath,
	}

	pollAndExecuteRemediation(rts.srv.Client(), cfg)

	if _, _, resultCalls := rts.snapshot(); resultCalls != 1 {
		t.Fatalf("resultCalls = %d, muốn đúng 1 lần báo remediate-result dù Executor không phản hồi", resultCalls)
	}

	rts.mu.Lock()
	gotResultReq := rts.lastResultReq
	rts.mu.Unlock()
	exitCode, _ := gotResultReq["exit_code"].(float64)
	if exitCode == 0 {
		t.Errorf("remediate-result exit_code = 0 dù Executor không phản hồi, muốn khác 0")
	}
	errMsg, _ := gotResultReq["error"].(string)
	if errMsg == "" {
		t.Errorf("remediate-result thiếu field error giải thích lý do thất bại")
	}
	if gotResultReq["job_id"] != float64(7) {
		t.Errorf("remediate-result job_id = %v, muốn 7", gotResultReq["job_id"])
	}
}

// TestPollAndExecuteRemediation_ExecutorRejectsSignatureStillReportsFailure
// mô phỏng Executor verify chữ ký thất bại (verified=false) — hành vi PHẢI
// giữ nguyên như scaffold hiện có: không extract/chạy gì, và Reporter vẫn
// phải báo remediate-result lỗi thay vì coi như thành công.
func TestPollAndExecuteRemediation_ExecutorRejectsSignatureStillReportsFailure(t *testing.T) {
	rts := newRemediateTestServer(t)
	rts.claimHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claimResponse{JobID: 9, ControlID: "CIS-3", RemediationRef: "ref-hong-chu-ky", DryRun: true})
	}
	rts.bundleHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(bundleResponse{
			RemediationRef:  "ref-hong-chu-ky",
			ContentTarGzB64: base64.StdEncoding.EncodeToString([]byte("tar")),
			SignatureAscB64: base64.StdEncoding.EncodeToString([]byte("sig")),
		})
	}
	sockPath, _ := startExecutorTestDouble(t, func(env jobEnvelope) (executionResult, bool) {
		return executionResult{Verified: false, Reason: "chữ ký không hợp lệ", Executed: false}, true
	})

	cfg := config{
		managerURL:         rts.srv.URL,
		hostname:           "h1",
		contentCacheDir:    t.TempDir(),
		executorSocketPath: sockPath,
	}
	pollAndExecuteRemediation(rts.srv.Client(), cfg)

	if _, _, resultCalls := rts.snapshot(); resultCalls != 1 {
		t.Fatalf("resultCalls = %d, muốn đúng 1 lần báo remediate-result khi verify thất bại", resultCalls)
	}
	rts.mu.Lock()
	gotResultReq := rts.lastResultReq
	rts.mu.Unlock()
	if exitCode, _ := gotResultReq["exit_code"].(float64); exitCode == 0 {
		t.Errorf("remediate-result exit_code = 0 dù Executor từ chối verify, muốn khác 0")
	}
}

func TestClaimRemediationJob_NoContentMeansNoJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := config{managerURL: srv.URL, hostname: "h1"}
	job, ok, err := claimRemediationJob(srv.Client(), cfg)
	if err != nil {
		t.Fatalf("claimRemediationJob() lỗi: %v", err)
	}
	if ok {
		t.Fatalf("ok = true cho 204, muốn false (không có job)")
	}
	if job != (claimResponse{}) {
		t.Fatalf("job = %+v, muốn zero value khi không có job", job)
	}
}

func TestClaimRemediationJob_OKParsesJobBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claimResponse{JobID: 5, ControlID: "C1", RemediationRef: "R1", DryRun: true})
	}))
	defer srv.Close()

	cfg := config{managerURL: srv.URL, hostname: "h1"}
	job, ok, err := claimRemediationJob(srv.Client(), cfg)
	if err != nil {
		t.Fatalf("claimRemediationJob() lỗi: %v", err)
	}
	if !ok {
		t.Fatalf("ok = false cho 200, muốn true")
	}
	if job.JobID != 5 || job.ControlID != "C1" || job.RemediationRef != "R1" || !job.DryRun {
		t.Fatalf("job = %+v, không khớp response", job)
	}
}

func TestClaimRemediationJob_UnexpectedStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("lỗi server"))
	}))
	defer srv.Close()

	cfg := config{managerURL: srv.URL, hostname: "h1"}
	if _, ok, err := claimRemediationJob(srv.Client(), cfg); err == nil || ok {
		t.Fatalf("muốn error + ok=false cho status 500, nhận ok=%v err=%v", ok, err)
	}
}
