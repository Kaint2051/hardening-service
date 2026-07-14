package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestGPGKeypair sinh 1 GPG key thật trong GNUPGHOME tạm (không đụng
// keyring thật của máy chạy test) — dùng cùng công cụ (gpg CLI) mà
// scripts/content-signing/*.sh dùng, không tự chế crypto trong test.
// t.Setenv("GNUPGHOME", ...) áp dụng cho CẢ helper này lẫn code sản phẩm
// (verifyBundleSignature exec.Command kế thừa env tiến trình test).
func newTestGPGKeypair(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg không có trong PATH — bỏ qua test cần GPG thật")
	}
	homeDir := t.TempDir()
	os.Chmod(homeDir, 0700)
	t.Setenv("GNUPGHOME", homeDir)

	batchFile := filepath.Join(homeDir, "keygen-batch")
	batch := "%no-protection\nKey-Type: RSA\nKey-Length: 2048\nName-Real: Test Signer\nName-Email: test-signer@example.com\nExpire-Date: 0\n%commit\n"
	if err := os.WriteFile(batchFile, []byte(batch), 0600); err != nil {
		t.Fatalf("ghi batch file thất bại: %v", err)
	}
	if out, err := exec.Command("gpg", "--batch", "--gen-key", batchFile).CombinedOutput(); err != nil {
		t.Fatalf("gpg --gen-key thất bại: %v\n%s", err, out)
	}

	out, err := exec.Command("gpg", "--list-secret-keys", "--with-colons", "--fingerprint").Output()
	if err != nil {
		t.Fatalf("liệt kê fingerprint thất bại: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fields := strings.Split(line, ":")
			if len(fields) > 9 {
				return fields[9]
			}
		}
	}
	t.Fatalf("không tìm thấy fingerprint trong output:\n%s", out)
	return ""
}

func writeSignedBundle(t *testing.T, bundleDir string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(bundleDir, 0700); err != nil {
		t.Fatalf("mkdir bundle thất bại: %v", err)
	}
	dataFile := filepath.Join(bundleDir, "content.tar.gz")
	sigFile := filepath.Join(bundleDir, "content.tar.gz.sig")
	if err := os.WriteFile(dataFile, content, 0600); err != nil {
		t.Fatalf("ghi content thất bại: %v", err)
	}
	out, err := exec.Command("gpg", "--batch", "--yes", "--detach-sign", "--armor", "--output", sigFile, dataFile).CombinedOutput()
	if err != nil {
		t.Fatalf("gpg --detach-sign thất bại: %v\n%s", err, out)
	}
}

func TestVerifyBundleSignature_ValidSignatureMatchingFingerprint(t *testing.T) {
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), []byte("nội dung remediation thật"))

	gotFingerprint, f, err := verifyBundleSignature(signedDir, "bundle-1", fingerprint)
	if err != nil {
		t.Fatalf("verifyBundleSignature lỗi dù chữ ký hợp lệ + fingerprint khớp: %v", err)
	}
	defer f.Close()
	if gotFingerprint != fingerprint {
		t.Fatalf("fingerprint trả về = %q, muốn %q", gotFingerprint, fingerprint)
	}
	// Verify thành công PHẢI trả về file đã seek về đầu, đọc lại được đúng
	// nguyên vẹn nội dung — đúng bất biến mà executeRemediation dựa vào để
	// giải nén không cần mở lại theo path (chống TOCTOU, xem verify.go).
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("đọc lại file trả về thất bại: %v", err)
	}
	if string(got) != "nội dung remediation thật" {
		t.Fatalf("nội dung file trả về = %q, không khớp bundle đã ký", got)
	}
}

// TestVerifyBundleSignature_ReturnedFileSurvivesPathReplacement chứng minh
// trực tiếp bất biến chống TOCTOU (xem docstring verifyBundleSignature,
// verify.go): mô phỏng ĐÚNG kịch bản Reporter (thành phần kém tin cậy hơn,
// lộ ra mạng) ghi đè content.tar.gz bằng writeFileAtomic (os.WriteFile +
// os.Rename, xem apps/agent/remediate.go) NGAY SAU KHI verify xong — file
// handle verifyBundleSignature trả về PHẢI vẫn đọc ra đúng nội dung ĐÃ được
// GPG xác thực, không bị ảnh hưởng bởi rename đè lên path.
func TestVerifyBundleSignature_ReturnedFileSurvivesPathReplacement(t *testing.T) {
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	bundleDir := filepath.Join(signedDir, "bundle-1")
	writeSignedBundle(t, bundleDir, []byte("nội dung ĐÃ verify"))

	_, f, err := verifyBundleSignature(signedDir, "bundle-1", fingerprint)
	if err != nil {
		t.Fatalf("verifyBundleSignature lỗi: %v", err)
	}
	defer f.Close()

	tmpPath := filepath.Join(bundleDir, "content.tar.gz.evil-tmp")
	if err := os.WriteFile(tmpPath, []byte("noi dung DOC HAI chua tung duoc ky"), 0600); err != nil {
		t.Fatalf("ghi file độc hại tạm thất bại: %v", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(bundleDir, "content.tar.gz")); err != nil {
		t.Fatalf("rename đè content.tar.gz thất bại: %v", err)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("đọc lại file đã verify thất bại: %v", err)
	}
	if string(got) != "nội dung ĐÃ verify" {
		t.Fatalf("file handle đọc ra %q SAU KHI path bị rename đè — TOCTOU: lẽ ra phải giữ nguyên nội dung ĐÃ verify", got)
	}
}

func TestVerifyBundleSignature_RejectsUntrustedFingerprint(t *testing.T) {
	newTestGPGKeypair(t)
	signedDir := t.TempDir()
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), []byte("nội dung remediation thật"))

	_, f, err := verifyBundleSignature(signedDir, "bundle-1", "0000000000000000000000000000000000000000")
	if err == nil {
		t.Fatalf("verifyBundleSignature không lỗi dù fingerprint không khớp danh sách tin cậy")
	}
	if f != nil {
		t.Fatalf("verifyBundleSignature trả về file handle không nil dù verify thất bại — có thể rò rỉ fd")
	}
}

func TestVerifyBundleSignature_RejectsTamperedContent(t *testing.T) {
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	bundleDir := filepath.Join(signedDir, "bundle-1")
	writeSignedBundle(t, bundleDir, []byte("nội dung gốc"))

	// Sửa content SAU khi ký — chữ ký detached không còn khớp, phải bị từ
	// chối dù chữ ký vẫn "tồn tại" và fingerprint ký ban đầu đúng là tin cậy.
	if err := os.WriteFile(filepath.Join(bundleDir, "content.tar.gz"), []byte("nội dung ĐÃ BỊ SỬA"), 0600); err != nil {
		t.Fatalf("ghi đè content thất bại: %v", err)
	}

	_, f, err := verifyBundleSignature(signedDir, "bundle-1", fingerprint)
	if err == nil {
		t.Fatalf("verifyBundleSignature không lỗi dù content đã bị sửa sau khi ký")
	}
	if f != nil {
		t.Fatalf("verifyBundleSignature trả về file handle không nil dù verify thất bại — có thể rò rỉ fd")
	}
}

func TestVerifyBundleSignature_MissingBundleReturnsError(t *testing.T) {
	newTestGPGKeypair(t) // đảm bảo gpg có sẵn, dù test này không cần key cụ thể
	_, _, err := verifyBundleSignature(t.TempDir(), "khong-ton-tai", "aaaa")
	if err == nil {
		t.Fatalf("verifyBundleSignature không lỗi dù bundle không tồn tại")
	}
}

func TestVerifyBundleSignature_EmptyRemediationRefRejected(t *testing.T) {
	_, _, err := verifyBundleSignature(t.TempDir(), "", "aaaa")
	if err == nil {
		t.Fatalf("verifyBundleSignature không lỗi dù remediation_ref rỗng")
	}
}

func TestVerifyBundleSignature_RejectsPathTraversal(t *testing.T) {
	signedDir := t.TempDir()
	// Đặt 1 file "victim" NGOÀI signedDir để chứng minh traversal thật sự có
	// thể chạm tới nếu không chặn — không chỉ kiểm tra chuỗi lỗi suông.
	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, "content.tar.gz"), []byte("victim"), 0600)

	traversalRefs := []string{
		"../" + filepath.Base(outsideDir),
		"..\\" + filepath.Base(outsideDir),
		"foo/../../bar",
		"/etc/passwd",
	}
	for _, ref := range traversalRefs {
		_, _, err := verifyBundleSignature(signedDir, ref, "aaaa")
		if err == nil {
			t.Fatalf("verifyBundleSignature(remediationRef=%q) không lỗi — path traversal không bị chặn", ref)
		}
	}
}

func TestVerifyBundleSignature_TimesOutOnHungGPG(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg không có trong PATH")
	}
	dir := t.TempDir()
	// Fake "gpg" treo vô thời hạn — đặt lên đầu PATH để verifyBundleSignature
	// (gọi exec.CommandContext(ctx, "gpg", ...)) chạy phải bản giả này.
	fakeGPG := filepath.Join(dir, "gpg")
	if err := os.WriteFile(fakeGPG, []byte("#!/bin/sh\nsleep 5\n"), 0755); err != nil {
		t.Fatalf("ghi fake gpg thất bại: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	signedDir := t.TempDir()
	bundleDir := filepath.Join(signedDir, "bundle-1")
	os.MkdirAll(bundleDir, 0700)
	os.WriteFile(filepath.Join(bundleDir, "content.tar.gz"), []byte("x"), 0600)
	os.WriteFile(filepath.Join(bundleDir, "content.tar.gz.sig"), []byte("x"), 0600)

	// Timeout ngắn (100ms) qua verifyBundleSignatureWithTimeout — test đường
	// timeout thật mà không phải đợi hết gpgVerifyTimeout thật (30s) hay hết
	// sleep 5s thật của fake gpg.
	const testTimeout = 100 * time.Millisecond
	start := time.Now()
	_, _, err := verifyBundleSignatureWithTimeout(signedDir, "bundle-1", "aaaa", testTimeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("verifyBundleSignatureWithTimeout không lỗi dù gpg treo")
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("verifyBundleSignatureWithTimeout mất %s — muốn dưới 5s (đợi hết sleep thật của fake gpg nghĩa là timeout không hoạt động)", elapsed)
	}
}

func TestParseValidSigFingerprint(t *testing.T) {
	status := "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG ABCDEF1234567890ABCDEF1234567890ABCDEF12 2026-01-01 1234567890 0 4 0 1 10 00 ABCDEF1234567890ABCDEF1234567890ABCDEF12\n[GNUPG:] TRUST_ULTIMATE\n"
	got := parseValidSigFingerprint(status)
	want := "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
	if got != want {
		t.Fatalf("parseValidSigFingerprint = %q, muốn %q", got, want)
	}
}

func TestParseValidSigFingerprint_NoValidSigReturnsEmpty(t *testing.T) {
	if got := parseValidSigFingerprint("[GNUPG:] ERRSIG ABCDEF\n"); got != "" {
		t.Fatalf("parseValidSigFingerprint = %q, muốn rỗng khi không có VALIDSIG", got)
	}
}
