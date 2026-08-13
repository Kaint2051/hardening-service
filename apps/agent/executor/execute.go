package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// backupPaths PHẢI đồng bộ TAY với danh sách y hệt trong
// apps/execution-env/remediate.sh (dòng
// `tar czf - /etc/ssh /etc/pam.d /etc/sysctl.conf /etc/sysctl.d /etc/security
// /etc/login.defs`) — 2 đường remediate (agentless qua execution-env,
// agent-based qua Executor này) phải backup đúng cùng phạm vi để "1-click
// restore" (app/jobs.py:run_restore, dùng chung result_summary.backup_tar_b64
// bất kể job tới từ đường nào) khôi phục đúng những gì đã đổi.
var backupPaths = []string{
	"/etc/ssh",
	"/etc/pam.d",
	"/etc/sysctl.conf",
	"/etc/sysctl.d",
	"/etc/security",
	"/etc/login.defs",
}

// maxExtractedBytes chặn zip-bomb (tổng dung lượng SAU giải nén, cộng dồn
// theo kích thước khai báo trong từng tar header — kiểm tra TRƯỚC khi copy
// dữ liệu thật của entry đó, không đợi ghi hết xong file khổng lồ rồi mới
// phát hiện). Executor giờ chạy ROOT (khác pass verify-only trước đây) nên
// rủi ro DoS ở bước giải nén nghiêm trọng hơn — 200 MiB dư sức cho 1 bundle
// remediation hợp lệ (playbook.yml + vài role nhỏ) nhưng vẫn chặn được nội
// dung ác ý cố tình phình to.
const maxExtractedBytes = 200 * 1024 * 1024

// maxExtractedEntries chặn RIÊNG kiểu zip-bomb "nhiều entry gần-như-rỗng"
// (hàng triệu tar.TypeDir/TypeSymlink) — maxExtractedBytes chỉ cộng dồn
// hdr.Size của tar.TypeReg, nên 1 bundle chữ ký hợp lệ chứa hàng triệu thư
// mục/symlink rỗng có thể vượt xa giới hạn về SỐ LƯỢNG (mỗi entry vẫn tốn 1
// lần MkdirAll/Symlink/Link syscall thật) mà không hề chạm ngưỡng byte
// (phát hiện qua rà soát đối kháng). 100.000 entry dư sức cho bundle
// Ansible hợp lệ (thường vài chục tới vài trăm file).
const maxExtractedEntries = 100_000

// extractBundle mở dataFile theo PATH rồi giải nén — dùng cho test/tiện ích
// khi caller CHƯA sẵn 1 *os.File đã mở (vd fixture cố định trong test). Ở
// đường sản phẩm thật (executeRemediation), KHÔNG dùng hàm này — phải dùng
// extractBundleFromReader với ĐÚNG *os.File verifyBundleSignature đã trả về,
// xem docstring của hàm đó để biết lý do (chống TOCTOU giữa verify và
// extract khi 2 bước đọc file theo 2 đường dẫn độc lập).
func extractBundle(dataFile, destDir string) error {
	f, err := os.Open(dataFile)
	if err != nil {
		return fmt.Errorf("mở bundle %q thất bại: %w", dataFile, err)
	}
	defer f.Close()
	return extractBundleFromReader(context.Background(), f, destDir)
}

// extractBundleFromReader giải nén content.tar.gz (đọc từ r — PHẢI là CHÍNH
// dữ liệu đã qua verifyBundleSignature, không phải mở lại theo path) vào
// destDir bằng archive/tar + compress/gzip CHUẨN CỦA GO — không shell ra lệnh
// `tar` (khác captureBackup bên dưới, nơi input là danh sách path CỐ ĐỊNH do
// chính code này chọn, không phải nội dung bundle không đáng tin).
//
// Chặn zip-slip bằng ĐÚNG 2 lớp đã dùng cho remediation_ref ở verify.go:
//  1. Tên entry (sau filepath.Clean) không được là đường dẫn tuyệt đối hay
//     bắt đầu bằng "..".
//  2. Containment check: đường dẫn đích SAU KHI Join+Clean vẫn phải nằm
//     trong destDir — phòng trường hợp lớp 1 có lỗ hổng chưa lường hết.
//
// Symlink/hardlink áp dụng thêm cùng 2 lớp đó cho TARGET của link (không chỉ
// tên entry) — 1 tar hợp lệ vẫn có thể chứa symlink trỏ ra ngoài dù chính tên
// entry của nó nằm trong destDir.
//
// ctx được kiểm tra ĐẦU MỖI VÒNG LẶP (giữa 2 entry) — không bọc quanh
// io.CopyN của MỘT entry đơn lẻ (đã bị chặn riêng bởi maxExtractedBytes/
// entry, copy tối đa 200 MiB thực tế chỉ mất dưới vài giây) — đủ để chặn
// kiểu zip-bomb "rất nhiều entry" (giữ trước đây HOÀN TOÀN không có bất kỳ
// giới hạn thời gian nào cho vòng lặp này, mâu thuẫn với comment của chính
// executeRemediation khẳng định bước này nằm trong context.WithTimeout).
func extractBundleFromReader(ctx context.Context, r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("bundle không phải gzip hợp lệ: %w", err)
	}
	defer gz.Close()

	destDirClean := filepath.Clean(destDir)
	tr := tar.NewReader(gz)
	var totalBytes int64
	var entryCount int

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("giải nén bundle bị hủy (vượt timeout hoặc bị cancel): %w", err)
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("đọc tar entry thất bại: %w", err)
		}
		entryCount++
		if entryCount > maxExtractedEntries {
			return fmt.Errorf("bundle giải nén vượt %d entry — từ chối (chống zip-bomb kiểu nhiều entry nhỏ/rỗng)", maxExtractedEntries)
		}

		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("tar entry %q không hợp lệ (đường dẫn tuyệt đối hoặc thoát ra ngoài thư mục đích)", hdr.Name)
		}
		target := filepath.Join(destDir, name)
		if target != destDirClean && !strings.HasPrefix(target, destDirClean+string(filepath.Separator)) {
			return fmt.Errorf("tar entry %q thoát ra ngoài thư mục đích", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0700); err != nil {
				return fmt.Errorf("tạo thư mục %q thất bại: %w", name, err)
			}

		case tar.TypeReg:
			totalBytes += hdr.Size
			if totalBytes > maxExtractedBytes || hdr.Size < 0 {
				return fmt.Errorf("bundle giải nén vượt %d byte — từ chối (chống zip-bomb)", maxExtractedBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return fmt.Errorf("tạo thư mục cha cho %q thất bại: %w", name, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode&0o777))
			if err != nil {
				return fmt.Errorf("tạo file %q thất bại: %w", name, err)
			}
			_, copyErr := io.CopyN(out, tr, hdr.Size)
			closeErr := out.Close()
			if copyErr != nil {
				return fmt.Errorf("ghi nội dung file %q thất bại: %w", name, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("đóng file %q thất bại: %w", name, closeErr)
			}

		case tar.TypeSymlink:
			resolved := filepath.Clean(hdr.Linkname)
			if !filepath.IsAbs(hdr.Linkname) {
				resolved = filepath.Clean(filepath.Join(filepath.Dir(target), hdr.Linkname))
			}
			if resolved != destDirClean && !strings.HasPrefix(resolved, destDirClean+string(filepath.Separator)) {
				return fmt.Errorf("tar entry %q (symlink) trỏ ra ngoài thư mục đích: %q", hdr.Name, hdr.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return fmt.Errorf("tạo thư mục cha cho %q thất bại: %w", name, err)
			}
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("tạo symlink %q thất bại: %w", name, err)
			}

		case tar.TypeLink:
			// Hardlink trong định dạng tar: Linkname tham chiếu 1 entry KHÁC
			// trong CHÍNH archive này, tính từ gốc giải nén (destDir) — khác
			// symlink (tính theo thư mục chứa chính nó).
			resolved := filepath.Clean(filepath.Join(destDir, hdr.Linkname))
			if resolved != destDirClean && !strings.HasPrefix(resolved, destDirClean+string(filepath.Separator)) {
				return fmt.Errorf("tar entry %q (hardlink) trỏ ra ngoài thư mục đích: %q", hdr.Name, hdr.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return fmt.Errorf("tạo thư mục cha cho %q thất bại: %w", name, err)
			}
			os.Remove(target)
			if err := os.Link(resolved, target); err != nil {
				return fmt.Errorf("tạo hardlink %q thất bại: %w", name, err)
			}

		default:
			// Nội dung remediation hợp lệ (playbook Ansible + role files) không
			// cần char/block device, FIFO... — từ chối thẳng an toàn hơn cố xử
			// lý loại entry không lường trước được, nhất là khi Executor giờ
			// chạy root.
			return fmt.Errorf("tar entry %q có kiểu không được hỗ trợ (typeflag=%d)", hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}

// tail cắt lấy n ký tự CUỐI của s — dùng cho LogTail (giữ phần kết quả gần
// nhất, hữu ích nhất khi output ansible-playbook dài).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// runAnsiblePlaybook chạy `ansible-playbook -i localhost, -c local
// [--check --diff nếu dryRun] <playbookPath>` — "-c local" (connection
// plugin local) vì Executor chạy NGAY TRÊN máy đích, không qua SSH (khác
// apps/execution-env/remediate.sh, chạy từ execution-env container SANG máy
// đích qua SSH). Tái dùng ĐÚNG pattern chống treo subprocess-tự-fork-con của
// verify.go/scan.go: process group riêng (Setpgid) + kill cả group khi
// context hết hạn (cmd.Cancel) + WaitDelay chờ dọn dẹp trước khi ép SIGKILL
// dứt điểm.
func runAnsiblePlaybook(ctx context.Context, ansibleBinary, playbookPath string, dryRun bool) (exitCode int, output string, err error) {
	args := []string{"-i", "localhost,", "-c", "local"}
	if dryRun {
		args = append(args, "--check", "--diff")
	}
	args = append(args, playbookPath)

	cmd := exec.CommandContext(ctx, ansibleBinary, args...)
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	if startErr := cmd.Start(); startErr != nil {
		return -1, "", fmt.Errorf("khởi động %s thất bại: %w", ansibleBinary, startErr)
	}
	runErr := cmd.Wait()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return -1, outBuf.String(), fmt.Errorf("%s vượt timeout, đã bị kill", ansibleBinary)
	}

	if runErr == nil {
		return 0, outBuf.String(), nil
	}
	exitErr, ok := runErr.(*exec.ExitError)
	if !ok {
		return -1, outBuf.String(), fmt.Errorf("chạy %s thất bại: %w", ansibleBinary, runErr)
	}
	return exitErr.ExitCode(), outBuf.String(), nil
}

// captureBackup chụp backup CÁC PATH CỐ ĐỊNH (backupPaths, không phải nội
// dung bundle) qua `tar czf - <backupPaths...>` rồi base64-encode stdout —
// PHẢI chạy TRƯỚC runAnsiblePlaybook khi apply thật (nguyên tắc cốt lõi #7:
// "backup được tạo TRƯỚC khi remediate"). Cùng pattern chống treo
// Setpgid+Cancel+WaitDelay; input là danh sách path do CHÍNH code này liệt
// kê (không phải dữ liệu từ bundle không đáng tin) nên không cần shell ra
// archive/tar của Go — dùng thẳng binary `tar` hệ thống, khớp đúng lệnh
// remediate.sh đã dùng cho đường agentless.
func captureBackup(ctx context.Context) (string, error) {
	args := append([]string{"czf", "-"}, backupPaths...)
	cmd := exec.CommandContext(ctx, "tar", args...)
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	// stderr bỏ qua (2>/dev/null tinh thần remediate.sh) — 1 số path trong
	// backupPaths có thể không tồn tại trên mọi host/distro, tar vẫn đóng gói
	// được phần còn lại, không nên fail cả remediate chỉ vì thiếu 1 thư mục
	// backup tuỳ chọn.
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	if startErr := cmd.Start(); startErr != nil {
		return "", fmt.Errorf("khởi động tar backup thất bại: %w", startErr)
	}
	runErr := cmd.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("tar backup vượt timeout, đã bị kill")
	}
	// Không chặn theo exit code của tar (có thể khác 0 nếu 1 vài path trong
	// backupPaths thiếu/đổi lúc đọc) — chỉ chặn nếu tiến trình không chạy
	// được gì (ExitError nghĩa là NÓ ĐÃ CHẠY và tự thoát, chấp nhận được).
	if runErr != nil {
		if _, ok := runErr.(*exec.ExitError); !ok {
			return "", fmt.Errorf("chạy tar backup thất bại: %w", runErr)
		}
	}
	return base64.StdEncoding.EncodeToString([]byte(outBuf.String())), nil
}

// executeRemediation orchestrate toàn bộ 1 job remediate: verify chữ ký ->
// giải nén bundle -> (nếu apply thật) backup TRƯỚC -> chạy ansible-playbook.
// Toàn bộ (trừ verify chữ ký, có timeout RIÊNG 30s cố định — xem verify.go)
// nằm trong 1 context.WithTimeout(cfg.remediationTimeout).
func executeRemediation(cfg executorConfig, env jobEnvelope) executionResult {
	fingerprint, dataFile, err := verifyBundleSignature(cfg.signedContentDir, env.RemediationRef, cfg.trustedFingerprint)
	if err != nil {
		// Verify thất bại: KHÔNG extract/chạy gì cả, giữ nguyên hành vi cũ.
		return executionResult{Verified: false, SignerFingerprint: fingerprint, Reason: err.Error(), Executed: false}
	}
	defer dataFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.remediationTimeout)
	defer cancel()

	workDir, err := os.MkdirTemp("", "executor-remediate-")
	if err != nil {
		return executionResult{
			Verified: true, SignerFingerprint: fingerprint, Executed: false,
			Reason: fmt.Sprintf("tạo thư mục làm việc tạm thất bại: %v", err),
		}
	}
	defer os.RemoveAll(workDir)

	// dataFile — ĐÚNG file handle verifyBundleSignature vừa xác thực (đã seek
	// về đầu), KHÔNG mở lại content.tar.gz theo path lần thứ 2 — xem docstring
	// verifyBundleSignature (verify.go) để biết lý do (chống TOCTOU).
	if err := extractBundleFromReader(ctx, dataFile, workDir); err != nil {
		return executionResult{
			Verified: true, SignerFingerprint: fingerprint, Executed: false,
			Reason: fmt.Sprintf("giải nén bundle thất bại: %v", err),
		}
	}

	playbookPath := filepath.Join(workDir, "playbook.yml")
	if _, statErr := os.Stat(playbookPath); statErr != nil {
		return executionResult{
			Verified: true, SignerFingerprint: fingerprint, Executed: false,
			Reason: fmt.Sprintf("bundle %q không có playbook.yml sau khi giải nén: %v", env.RemediationRef, statErr),
		}
	}

	var backupB64 string
	if !env.DryRun {
		b64, backupErr := captureBackup(ctx)
		if backupErr != nil {
			return executionResult{
				Verified: true, SignerFingerprint: fingerprint, Executed: false,
				Reason: fmt.Sprintf("backup cấu hình TRƯỚC khi apply thất bại (từ chối apply, nguyên tắc cốt lõi #7): %v", backupErr),
			}
		}
		backupB64 = b64
	}

	exitCode, output, runErr := runAnsiblePlaybook(ctx, cfg.ansibleBinary, playbookPath, env.DryRun)
	if runErr != nil {
		result := executionResult{
			Verified: true, SignerFingerprint: fingerprint, Executed: false,
			Reason:  fmt.Sprintf("chạy %s thất bại: %v", cfg.ansibleBinary, runErr),
			LogTail: tail(output, 4000),
		}
		if !env.DryRun {
			result.BackupTarB64 = backupB64
		}
		return result
	}

	result := executionResult{
		Verified: true, SignerFingerprint: fingerprint, Executed: true,
		ExitCode: exitCode, LogTail: tail(output, 4000),
	}
	if env.DryRun {
		result.DiffOutput = output
	} else {
		result.BackupTarB64 = backupB64
	}
	return result
}

// executeRestore giải nén backup base64 (KHÔNG qua đường verify GPG — khác
// remediation bundle; mô hình tin cậy giữ NGUYÊN như đường SSH hiện có,
// apps/execution-env/restore.sh: backup blob không có chữ ký riêng, tin cậy
// nhờ đã đi qua DB/kênh mTLS đã xác thực của Orchestrator, xem app/jobs.py:
// run_restore) đè lên các path đã backup, rồi CHỈ reload sshd nếu `sshd -t`
// pass — mirror ĐÚNG logic an toàn của restore.sh (không reload nếu config
// lỗi, để nguyên file trên đĩa cho operator tự soát) nhưng chạy LOCAL
// (Executor đã root ngay trên máy đích, không cần round-trip SSH).
func executeRestore(cfg executorConfig, env jobEnvelope) executionResult {
	raw, err := base64.StdEncoding.DecodeString(env.BackupTarB64)
	if err != nil {
		return executionResult{Verified: true, Executed: false, Reason: fmt.Sprintf("backup_tar_b64 không decode được: %v", err)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.remediationTimeout)
	defer cancel()

	extractCode, extractOutput, err := runTarExtractToRoot(ctx, raw)
	if err != nil {
		return executionResult{Verified: true, Executed: false, Reason: fmt.Sprintf("giải nén backup thất bại: %v", err), LogTail: tail(extractOutput, 4000)}
	}
	if extractCode != 0 {
		return executionResult{
			Verified: true, Executed: false,
			Reason:  fmt.Sprintf("tar xzf giải nén backup thoát mã %d", extractCode),
			LogTail: tail(extractOutput, 4000),
		}
	}

	// sshd_config nằm trong phạm vi backup (/etc/ssh) — kiểm tra hợp lệ
	// TRƯỚC khi reload, tránh tự khoá SSH nếu backup vì lý do nào đó không
	// toàn vẹn. KHÔNG reload nếu test lỗi — để nguyên file đã ghi trên đĩa,
	// báo lỗi rõ ràng cho operator tự kiểm tra tay thay vì reload mù rồi mất
	// kết nối (y hệt restore.sh:60-71, chỉ khác chạy local không qua SSH).
	testCode, testOutput, testErr := runSimpleCommand(ctx, "sshd", "-t")
	if testErr != nil || testCode != 0 {
		return executionResult{
			Verified: true, Executed: false,
			Reason: fmt.Sprintf(
				"sshd_config sau restore KHÔNG hợp lệ (sshd -t thoát mã %d) — ĐÃ giải nén backup lên đĩa "+
					"nhưng KHÔNG reload để tránh tự khoá SSH, cần vào tay kiểm tra: %v", testCode, testErr,
			),
			LogTail: tail(extractOutput+"\n"+testOutput, 4000),
		}
	}

	// reload sshd, fallback ssh — cùng cách restore.sh làm
	// (`systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true`).
	reloadCode, reloadOutput, _ := runSimpleCommand(ctx, "systemctl", "reload", "sshd")
	if reloadCode != 0 {
		reloadCode, reloadOutput, _ = runSimpleCommand(ctx, "systemctl", "reload", "ssh")
	}
	return executionResult{
		Verified: true, Executed: true, ExitCode: reloadCode,
		LogTail: tail(extractOutput+"\n"+testOutput+"\n"+reloadOutput, 4000),
	}
}

// runTarExtractToRoot chạy `tar xzf - -C /` với stdin là backup đã decode —
// KHÔNG dùng archive/tar của Go như extractBundleFromReader (bundle không
// đáng tin, cần chống zip-slip/zip-bomb) vì backup ở đây do CHÍNH Orchestrator
// đã xác thực chuyển xuống (mirror ĐÚNG cách restore.sh gọi `tar xzf -` thẳng
// qua SSH, không có lớp kiểm tra path riêng nào ở đó cả).
func runTarExtractToRoot(ctx context.Context, data []byte) (exitCode int, output string, err error) {
	cmd := exec.CommandContext(ctx, "tar", "xzf", "-", "-C", "/")
	cmd.Stdin = bytes.NewReader(data)
	return runCmd(ctx, cmd)
}

// runSimpleCommand chạy 1 lệnh hệ thống ngắn (sshd -t, systemctl reload...)
// — cùng pattern chống treo Setpgid+Cancel+WaitDelay như runAnsiblePlaybook/
// captureBackup ở trên, tách riêng vì 2 hàm đó có tham số/semantics đặc thù
// riêng (ansible args, bỏ qua exit code khác 0) không dùng chung được.
func runSimpleCommand(ctx context.Context, name string, args ...string) (exitCode int, output string, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return runCmd(ctx, cmd)
}

func runCmd(ctx context.Context, cmd *exec.Cmd) (exitCode int, output string, err error) {
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	if startErr := cmd.Start(); startErr != nil {
		return -1, "", fmt.Errorf("khởi động %s thất bại: %w", cmd.Path, startErr)
	}
	runErr := cmd.Wait()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return -1, outBuf.String(), fmt.Errorf("%s vượt timeout, đã bị kill", cmd.Path)
	}
	if runErr == nil {
		return 0, outBuf.String(), nil
	}
	exitErr, ok := runErr.(*exec.ExitError)
	if !ok {
		return -1, outBuf.String(), fmt.Errorf("chạy %s thất bại: %w", cmd.Path, runErr)
	}
	return exitErr.ExitCode(), outBuf.String(), nil
}
