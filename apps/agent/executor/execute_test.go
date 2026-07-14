package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------- extractBundle ----------------

// tarEntry mô tả 1 entry sẽ ghi vào tar.gz fixture dùng cho test — đủ trường
// để dựng cả file thường, thư mục, symlink.
type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

// buildTarGz dựng 1 tar.gz HỢP LỆ hoàn toàn bằng archive/tar + compress/gzip
// của Go (không gọi binary `tar` ngoài) — đúng yêu cầu test tự dựng fixture.
func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0644,
			Size:     int64(len(e.body)),
			Typeflag: e.typeflag,
			Linkname: e.linkname,
		}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag == tar.TypeDir {
			hdr.Mode = 0755
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("ghi tar header %q thất bại: %v", e.name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("ghi tar body %q thất bại: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("đóng tar writer thất bại: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("đóng gzip writer thất bại: %v", err)
	}
	return buf.Bytes()
}

func writeTarGzFile(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "content.tar.gz")
	if err := os.WriteFile(path, buildTarGz(t, entries), 0600); err != nil {
		t.Fatalf("ghi file tar.gz thất bại: %v", err)
	}
	return path
}

func TestExtractBundle_ExtractsValidTarGz(t *testing.T) {
	dataFile := writeTarGzFile(t, []tarEntry{
		{name: "playbook.yml", body: "---\n- hosts: localhost\n"},
		{name: "roles/", typeflag: tar.TypeDir},
		{name: "roles/foo.yml", body: "role content"},
	})
	destDir := t.TempDir()

	if err := extractBundle(dataFile, destDir); err != nil {
		t.Fatalf("extractBundle lỗi dù tar hợp lệ: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, "playbook.yml"))
	if err != nil || string(got) != "---\n- hosts: localhost\n" {
		t.Fatalf("nội dung playbook.yml sau giải nén sai: got=%q err=%v", got, err)
	}
	got2, err := os.ReadFile(filepath.Join(destDir, "roles/foo.yml"))
	if err != nil || string(got2) != "role content" {
		t.Fatalf("nội dung roles/foo.yml sau giải nén sai: got=%q err=%v", got2, err)
	}
}

func TestExtractBundle_RejectsPathTraversalEntry(t *testing.T) {
	dataFile := writeTarGzFile(t, []tarEntry{
		{name: "../evil", body: "pwned"},
	})
	destDir := t.TempDir()

	if err := extractBundle(dataFile, destDir); err == nil {
		t.Fatalf("extractBundle không lỗi dù tar entry chứa \"..\" — path traversal không bị chặn")
	}
	// Chứng minh traversal thật sự có thể chạm tới nếu không chặn, không chỉ
	// kiểm tra chuỗi lỗi suông (cùng tinh thần TestVerifyBundleSignature_RejectsPathTraversal).
	if _, err := os.Stat(filepath.Join(filepath.Dir(destDir), "evil")); !os.IsNotExist(err) {
		t.Fatalf("file 'evil' đã bị ghi RA NGOÀI destDir")
	}
}

func TestExtractBundle_RejectsAbsolutePathEntry(t *testing.T) {
	dataFile := writeTarGzFile(t, []tarEntry{
		{name: "/etc/evil-absolute", body: "pwned"},
	})
	destDir := t.TempDir()

	if err := extractBundle(dataFile, destDir); err == nil {
		t.Fatalf("extractBundle không lỗi dù tar entry có đường dẫn TUYỆT ĐỐI")
	}
}

func TestExtractBundle_RejectsSymlinkEscapingDestDir(t *testing.T) {
	outsideDir := t.TempDir()
	dataFile := writeTarGzFile(t, []tarEntry{
		{name: "evil-link", typeflag: tar.TypeSymlink, linkname: filepath.Join(outsideDir, "victim")},
	})
	destDir := t.TempDir()

	if err := extractBundle(dataFile, destDir); err == nil {
		t.Fatalf("extractBundle không lỗi dù symlink trỏ RA NGOÀI destDir (tuyệt đối)")
	}
}

func TestExtractBundle_RejectsRelativeSymlinkEscapingDestDir(t *testing.T) {
	dataFile := writeTarGzFile(t, []tarEntry{
		{name: "sub/evil-link", typeflag: tar.TypeSymlink, linkname: "../../../etc/passwd"},
	})
	destDir := t.TempDir()

	if err := extractBundle(dataFile, destDir); err == nil {
		t.Fatalf("extractBundle không lỗi dù symlink TƯƠNG ĐỐI trỏ ra ngoài destDir")
	}
}

func TestExtractBundle_AllowsSymlinkWithinDestDir(t *testing.T) {
	dataFile := writeTarGzFile(t, []tarEntry{
		{name: "real.txt", body: "nội dung thật"},
		{name: "link.txt", typeflag: tar.TypeSymlink, linkname: "real.txt"},
	})
	destDir := t.TempDir()

	if err := extractBundle(dataFile, destDir); err != nil {
		t.Fatalf("extractBundle lỗi dù symlink nằm HOÀN TOÀN trong destDir: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "link.txt"))
	if err != nil || string(got) != "nội dung thật" {
		t.Fatalf("đọc qua symlink hợp lệ thất bại: got=%q err=%v", got, err)
	}
}

func TestExtractBundle_RejectsOversizedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "content.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("tạo file fixture thất bại: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	size := int64(maxExtractedBytes) + 1
	if err := tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0644, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("ghi header fixture thất bại: %v", err)
	}
	// Buffer toàn số 0 nén cực tốt qua gzip — file .tar.gz kết quả chỉ vài KB
	// dù khai báo Size > 200 MiB, nhưng vẫn là 1 tar HỢP LỆ (đủ số byte đã
	// khai) để không bị tar.Writer từ chối lúc dựng fixture.
	buf := make([]byte, 1<<20)
	var written int64
	for written < size {
		n := int64(len(buf))
		if remaining := size - written; remaining < n {
			n = remaining
		}
		if _, err := tw.Write(buf[:n]); err != nil {
			t.Fatalf("ghi body fixture thất bại: %v", err)
		}
		written += n
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("đóng tar writer thất bại: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("đóng gzip writer thất bại: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("đóng file fixture thất bại: %v", err)
	}

	destDir := t.TempDir()
	if err := extractBundle(path, destDir); err == nil {
		t.Fatalf("extractBundle không lỗi dù tổng dung lượng khai báo vượt %d byte", maxExtractedBytes)
	}
}

// ---------------- runAnsiblePlaybook ----------------

func writeFakeAnsiblePlaybook(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake ansible-playbook là shell script — chỉ chạy trên Linux (môi trường build/test thật)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible-playbook")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("ghi fake ansible-playbook thất bại: %v", err)
	}
	return path
}

func TestRunAnsiblePlaybook_DryRunPassesCheckDiffFlags(t *testing.T) {
	fake := writeFakeAnsiblePlaybook(t, "#!/bin/sh\necho \"ARGS:$@\"\nexit 0\n")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exitCode, output, err := runAnsiblePlaybook(ctx, fake, "/tmp/playbook.yml", true)
	if err != nil {
		t.Fatalf("runAnsiblePlaybook lỗi: %v (output=%s)", err, output)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, muốn 0 — output=%s", exitCode, output)
	}
	if !strings.Contains(output, "--check") || !strings.Contains(output, "--diff") {
		t.Fatalf("output không chứa --check/--diff đã truyền cho dry-run: %s", output)
	}
}

func TestRunAnsiblePlaybook_ApplyDoesNotPassCheckDiffFlags(t *testing.T) {
	fake := writeFakeAnsiblePlaybook(t, "#!/bin/sh\necho \"ARGS:$@\"\nexit 0\n")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, output, err := runAnsiblePlaybook(ctx, fake, "/tmp/playbook.yml", false)
	if err != nil {
		t.Fatalf("runAnsiblePlaybook lỗi: %v", err)
	}
	if strings.Contains(output, "--check") || strings.Contains(output, "--diff") {
		t.Fatalf("apply thật KHÔNG được truyền --check/--diff, output=%s", output)
	}
}

func TestRunAnsiblePlaybook_PropagatesNonZeroExitCode(t *testing.T) {
	fake := writeFakeAnsiblePlaybook(t, "#!/bin/sh\nexit 3\n")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exitCode, _, err := runAnsiblePlaybook(ctx, fake, "/tmp/playbook.yml", false)
	if err != nil {
		t.Fatalf("runAnsiblePlaybook lỗi dù chỉ exit code khác 0 (không phải lỗi thực thi): %v", err)
	}
	if exitCode != 3 {
		t.Fatalf("exitCode = %d, muốn 3", exitCode)
	}
}

func TestRunAnsiblePlaybook_TimesOutOnHungProcess(t *testing.T) {
	fake := writeFakeAnsiblePlaybook(t, "#!/bin/sh\nsleep 5\n")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := runAnsiblePlaybook(ctx, fake, "/tmp/playbook.yml", false)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("runAnsiblePlaybook không lỗi dù tiến trình treo quá timeout")
	}
	if elapsed >= 4*time.Second {
		t.Fatalf("runAnsiblePlaybook mất %s — muốn dưới 4s (đợi hết sleep 5s thật nghĩa là timeout không hoạt động)", elapsed)
	}
}

// ---------------- captureBackup ----------------

func TestCaptureBackup_ReturnsBase64EncodedTarOfConfiguredPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cần binary tar thật")
	}
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar không có trong PATH")
	}

	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "marker.conf"), []byte("hello backup"), 0644); err != nil {
		t.Fatalf("ghi fixture thất bại: %v", err)
	}

	// backupPaths là package-level var (không phải const) CHÍNH để test override
	// được bằng 1 thư mục fixture tạm thay vì đụng /etc thật của máy chạy test.
	original := backupPaths
	backupPaths = []string{fixtureDir}
	defer func() { backupPaths = original }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b64, err := captureBackup(ctx)
	if err != nil {
		t.Fatalf("captureBackup lỗi: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("backup không phải base64 hợp lệ: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("backup không phải gzip hợp lệ: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("đọc tar backup thất bại: %v", err)
		}
		if strings.HasSuffix(hdr.Name, "marker.conf") {
			found = true
			body, _ := io.ReadAll(tr)
			if string(body) != "hello backup" {
				t.Fatalf("nội dung marker.conf trong backup = %q, muốn %q", body, "hello backup")
			}
		}
	}
	if !found {
		t.Fatalf("backup không chứa marker.conf từ fixtureDir đã override backupPaths")
	}
}

func TestCaptureBackup_TimesOutOnHungTar(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake tar là shell script — chỉ chạy trên Linux")
	}
	dir := t.TempDir()
	fakeTar := filepath.Join(dir, "tar")
	if err := os.WriteFile(fakeTar, []byte("#!/bin/sh\nsleep 5\n"), 0755); err != nil {
		t.Fatalf("ghi fake tar thất bại: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := captureBackup(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("captureBackup không lỗi dù tar treo quá timeout")
	}
	if elapsed >= 4*time.Second {
		t.Fatalf("captureBackup mất %s — muốn dưới 4s", elapsed)
	}
}

// ---------------- executeRemediation (end-to-end) ----------------

// minimalPlaybook ghi 1 dòng cố định vào targetPath qua module `copy` —
// module này hỗ trợ --diff thật (khác `debug`), nên dry-run thật sự cho ra
// DiffOutput không rỗng, và apply thật sự tạo/đổi file kiểm chứng được.
func minimalPlaybook(targetPath string) string {
	return "---\n" +
		"- hosts: localhost\n" +
		"  connection: local\n" +
		"  gather_facts: false\n" +
		"  tasks:\n" +
		"    - name: ghi marker remediation\n" +
		"      copy:\n" +
		"        content: \"remediated-by-executor-test\\n\"\n" +
		"        dest: \"" + targetPath + "\"\n"
}

func requireAnsiblePlaybookBinary(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook không có trong PATH — bỏ qua test end-to-end cần ansible-core thật")
	}
}

func TestExecuteRemediation_VerifyFailureDoesNotExecute(t *testing.T) {
	requireAnsiblePlaybookBinary(t)
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	targetPath := filepath.Join(t.TempDir(), "marker.txt")
	bundleBytes := buildTarGz(t, []tarEntry{{name: "playbook.yml", body: minimalPlaybook(targetPath)}})
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), bundleBytes)
	_ = fingerprint // chữ ký hợp lệ, nhưng ta cố tình dùng fingerprint tin cậy SAI bên dưới

	cfg := executorConfig{
		signedContentDir:   signedDir,
		trustedFingerprint: "0000000000000000000000000000000000000000",
		remediationTimeout: 30 * time.Second,
		ansibleBinary:      "ansible-playbook",
	}
	result := executeRemediation(cfg, jobEnvelope{ControlID: "CIS-1.1", RemediationRef: "bundle-1", DryRun: true})

	if result.Verified {
		t.Fatalf("Verified = true, muốn false (fingerprint tin cậy không khớp)")
	}
	if result.Executed {
		t.Fatalf("Executed = true, muốn false — verify thất bại KHÔNG được extract/chạy gì")
	}
	if result.Reason == "" {
		t.Fatalf("thiếu Reason giải thích lý do từ chối")
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("targetPath đã bị tạo dù verify thất bại — có chạy nhầm ansible")
	}
}

func TestExecuteRemediation_VerifyPassDryRunDoesNotChangeSystem(t *testing.T) {
	requireAnsiblePlaybookBinary(t)
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	targetPath := filepath.Join(t.TempDir(), "marker.txt")
	bundleBytes := buildTarGz(t, []tarEntry{{name: "playbook.yml", body: minimalPlaybook(targetPath)}})
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), bundleBytes)

	cfg := executorConfig{
		signedContentDir:   signedDir,
		trustedFingerprint: fingerprint,
		remediationTimeout: 60 * time.Second,
		ansibleBinary:      "ansible-playbook",
	}
	result := executeRemediation(cfg, jobEnvelope{ControlID: "CIS-1.1", RemediationRef: "bundle-1", DryRun: true})

	if !result.Verified {
		t.Fatalf("Verified = false, muốn true — reason=%q", result.Reason)
	}
	if !result.Executed {
		t.Fatalf("Executed = false, muốn true — reason=%q logtail=%s", result.Reason, result.LogTail)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, muốn 0 — logtail=%s", result.ExitCode, result.LogTail)
	}
	if strings.TrimSpace(result.DiffOutput) == "" {
		t.Fatalf("DiffOutput rỗng cho dry-run tạo file mới (đáng lẽ phải thấy diff)")
	}
	if result.BackupTarB64 != "" {
		t.Fatalf("BackupTarB64 không rỗng cho dry-run — KHÔNG được backup khi chỉ dry-run")
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("targetPath đã được TẠO THẬT dù chỉ chạy dry-run (--check phải không đổi gì)")
	}
}

func TestExecuteRemediation_VerifyPassApplyChangesSystemAndBacksUpFirst(t *testing.T) {
	requireAnsiblePlaybookBinary(t)
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	targetPath := filepath.Join(t.TempDir(), "marker.txt")
	bundleBytes := buildTarGz(t, []tarEntry{{name: "playbook.yml", body: minimalPlaybook(targetPath)}})
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), bundleBytes)

	// Override backupPaths bằng 1 fixture xác định thay vì /etc thật của máy
	// chạy test (có thể thiếu/rỗng tuỳ base image) — đảm bảo test xác định.
	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, "marker.conf"), []byte("pre-apply state"), 0644); err != nil {
		t.Fatalf("ghi fixture backup thất bại: %v", err)
	}
	original := backupPaths
	backupPaths = []string{fixtureDir}
	defer func() { backupPaths = original }()

	cfg := executorConfig{
		signedContentDir:   signedDir,
		trustedFingerprint: fingerprint,
		remediationTimeout: 60 * time.Second,
		ansibleBinary:      "ansible-playbook",
	}
	result := executeRemediation(cfg, jobEnvelope{ControlID: "CIS-1.1", RemediationRef: "bundle-1", DryRun: false})

	if !result.Verified {
		t.Fatalf("Verified = false, muốn true — reason=%q", result.Reason)
	}
	if !result.Executed {
		t.Fatalf("Executed = false, muốn true — reason=%q logtail=%s", result.Reason, result.LogTail)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, muốn 0 — logtail=%s", result.ExitCode, result.LogTail)
	}
	if result.BackupTarB64 == "" {
		t.Fatalf("BackupTarB64 rỗng cho apply thật — PHẢI backup TRƯỚC khi đổi (nguyên tắc cốt lõi #7)")
	}
	if _, err := base64.StdEncoding.DecodeString(result.BackupTarB64); err != nil {
		t.Fatalf("BackupTarB64 không phải base64 hợp lệ: %v", err)
	}
	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("targetPath chưa được tạo dù apply thật đã chạy (exit_code=%d, logtail=%s): %v", result.ExitCode, result.LogTail, err)
	}
	if string(got) != "remediated-by-executor-test\n" {
		t.Fatalf("nội dung targetPath = %q, không khớp playbook đã áp dụng", got)
	}
}

func TestExecuteRemediation_MissingPlaybookYmlInBundle(t *testing.T) {
	requireAnsiblePlaybookBinary(t)
	fingerprint := newTestGPGKeypair(t)
	signedDir := t.TempDir()
	bundleBytes := buildTarGz(t, []tarEntry{{name: "README.md", body: "không có playbook.yml ở đây"}})
	writeSignedBundle(t, filepath.Join(signedDir, "bundle-1"), bundleBytes)

	cfg := executorConfig{
		signedContentDir:   signedDir,
		trustedFingerprint: fingerprint,
		remediationTimeout: 30 * time.Second,
		ansibleBinary:      "ansible-playbook",
	}
	result := executeRemediation(cfg, jobEnvelope{ControlID: "CIS-1.1", RemediationRef: "bundle-1", DryRun: true})

	if !result.Verified {
		t.Fatalf("Verified = false, muốn true (chữ ký hợp lệ, chỉ thiếu playbook.yml)")
	}
	if result.Executed {
		t.Fatalf("Executed = true, muốn false — bundle không có playbook.yml")
	}
	if result.Reason == "" {
		t.Fatalf("thiếu Reason giải thích lý do")
	}
}
