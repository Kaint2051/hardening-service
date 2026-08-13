package main

import (
	"encoding/json"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// testSocketGroup trả về tên group CHÍNH của tiến trình test hiện tại —
// đảm bảo tồn tại trên mọi máy chạy test (không hardcode "root", có thể
// không có sẵn trong 1 số môi trường tối giản) — dùng làm
// executorConfig.socketGroup giả lập trong test.
func testSocketGroup(t *testing.T) string {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Skipf("không lấy được user hiện tại — bỏ qua test cần group thật: %v", err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Skipf("không tìm được group cho gid %s — bỏ qua test cần group thật: %v", current.Gid, err)
	}
	return group.Name
}

func startTestExecutor(t *testing.T, cfg executorConfig) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(cfg)
	}()
	// serve() bind socket đồng bộ trước accept loop, nhưng không có tín hiệu
	// "đã sẵn sàng" — chờ ngắn rồi kiểm tra dial được chưa, đơn giản hơn
	// dựng thêm channel chỉ cho test.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", cfg.socketPath, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case err := <-errCh:
			t.Fatalf("serve() thoát sớm: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("executor không sẵn sàng nhận kết nối sau 2s")
}

func dialAndSendJob(t *testing.T, socketPath string, env jobEnvelope) executionResult {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("dial executor socket thất bại: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(env); err != nil {
		t.Fatalf("gửi job envelope thất bại: %v", err)
	}
	var result executionResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		t.Fatalf("đọc executionResult thất bại: %v", err)
	}
	return result
}

func TestServe_ValidJobReturnsVerifiedTrue(t *testing.T) {
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), []byte("nội dung remediation thật"))

	cfg := executorConfig{
		socketPath:         filepath.Join(t.TempDir(), "executor.sock"),
		signedContentDir:   signedDir,
		trustedFingerprint: fingerprint,
		socketGroup:        testSocketGroup(t),
	}
	startTestExecutor(t, cfg)

	result := dialAndSendJob(t, cfg.socketPath, jobEnvelope{ControlID: "CIS-1.1", RemediationRef: "bundle-1"})
	if !result.Verified {
		t.Fatalf("result.Verified = false, muốn true — reason=%q", result.Reason)
	}
	if result.SignerFingerprint != fingerprint {
		t.Fatalf("SignerFingerprint = %q, muốn %q", result.SignerFingerprint, fingerprint)
	}
}

func TestServe_UnknownBundleReturnsVerifiedFalse(t *testing.T) {
	newTestGPGKeypair(t)
	cfg := executorConfig{
		socketPath:         filepath.Join(t.TempDir(), "executor.sock"),
		signedContentDir:   t.TempDir(),
		trustedFingerprint: "deadbeef",
		socketGroup:        testSocketGroup(t),
	}
	startTestExecutor(t, cfg)

	result := dialAndSendJob(t, cfg.socketPath, jobEnvelope{ControlID: "CIS-1.1", RemediationRef: "khong-ton-tai"})
	if result.Verified {
		t.Fatalf("result.Verified = true, muốn false cho bundle không tồn tại")
	}
	if result.Reason == "" {
		t.Fatalf("thiếu Reason giải thích vì sao từ chối")
	}
}

func TestServe_InvalidJSONReturnsVerifiedFalse(t *testing.T) {
	cfg := executorConfig{
		socketPath:         filepath.Join(t.TempDir(), "executor.sock"),
		signedContentDir:   t.TempDir(),
		trustedFingerprint: "deadbeef",
		socketGroup:        testSocketGroup(t),
	}
	startTestExecutor(t, cfg)

	conn, err := net.DialTimeout("unix", cfg.socketPath, time.Second)
	if err != nil {
		t.Fatalf("dial thất bại: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("not json at all"))

	var result executionResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		t.Fatalf("đọc executionResult thất bại: %v", err)
	}
	if result.Verified {
		t.Fatalf("result.Verified = true, muốn false cho body không phải JSON")
	}
}

func TestServe_SocketFileIsGroupOwnedWithRestrictedPermissions(t *testing.T) {
	group := testSocketGroup(t)
	cfg := executorConfig{
		socketPath:         filepath.Join(t.TempDir(), "executor.sock"),
		signedContentDir:   t.TempDir(),
		trustedFingerprint: "deadbeef",
		socketGroup:        group,
	}
	startTestExecutor(t, cfg)

	// 0660 (chủ sở hữu + group, KHÔNG phải user khác trên máy) — thay cho
	// 0600 chỉ-chủ-sở-hữu trước đây, đúng mô hình group dùng chung Reporter
	// (khác user) ↔ Executor (xem server.go:serve()).
	info, err := os.Stat(cfg.socketPath)
	if err != nil {
		t.Fatalf("stat socket thất bại: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0660 {
		t.Fatalf("permission socket = %o, muốn 0660", perm)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("không lấy được owner/group thật của socket (syscall.Stat_t)")
	}
	wantGroup, err := user.LookupGroup(group)
	if err != nil {
		t.Fatalf("lookup lại group %q thất bại: %v", group, err)
	}
	wantGid, err := strconv.Atoi(wantGroup.Gid)
	if err != nil {
		t.Fatalf("gid %q của group %q không phải số hợp lệ: %v", wantGroup.Gid, group, err)
	}
	if int(stat.Gid) != wantGid {
		t.Fatalf("gid socket = %d, muốn %d (group %q)", stat.Gid, wantGid, group)
	}

	// Đường dẫn tạm (bind-then-rename) không được sót lại sau khi serve()
	// rename thành công sang đường dẫn thật.
	if _, err := os.Stat(cfg.socketPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("đường dẫn socket tạm vẫn còn sau khi rename xong: err=%v", err)
	}
}

func TestConnIOTimeout_CoversVerifyPlusRemediationPlusMargin(t *testing.T) {
	// Trước đây handleConn không đặt deadline nào lên conn — 1 client dial
	// rồi không gửi gì (Reporter compromised/lỗi, network glitch giữa chừng)
	// khiến goroutine treo VÔ THỜI HẠN. Test bằng số học trực tiếp (nhanh,
	// tất định) thay vì chờ thật hết deadline (connIOTimeout mặc định cỡ
	// gpgVerifyTimeout 30s cố định + remediationTimeout, quá chậm cho unit
	// test) — cùng mức độ (không quá) mà runProtected() phía Reporter cũng
	// không có test ép panic thật, chỉ test qua logic tương đương.
	cfg := executorConfig{remediationTimeout: 5 * time.Second}
	got := connIOTimeout(cfg)
	want := cfg.remediationTimeout + gpgVerifyTimeout + 30*time.Second
	if got != want {
		t.Fatalf("connIOTimeout() = %s, muốn %s (remediationTimeout + gpgVerifyTimeout + biên độ)", got, want)
	}
	if got <= cfg.remediationTimeout {
		t.Fatalf("connIOTimeout() = %s phải LỚN HƠN remediationTimeout (%s) — nếu không, deadline có thể hết TRƯỚC khi executeRemediation chạy xong hợp lệ", got, cfg.remediationTimeout)
	}
}

func TestServe_UnknownSocketGroupReturnsErrorWithoutCreatingRealSocket(t *testing.T) {
	cfg := executorConfig{
		socketPath:         filepath.Join(t.TempDir(), "executor.sock"),
		signedContentDir:   t.TempDir(),
		trustedFingerprint: "deadbeef",
		socketGroup:        "hardening-agent-group-khong-ton-tai-999",
	}

	if err := serve(cfg); err == nil {
		t.Fatalf("serve() không lỗi dù socketGroup không tồn tại")
	}
	if _, err := os.Stat(cfg.socketPath); !os.IsNotExist(err) {
		t.Fatalf("đường dẫn socket thật không được phép tồn tại khi group cấu hình không hợp lệ")
	}
}
