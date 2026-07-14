package main

import (
	"bufio"
	"context"
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

// gpgVerifyTimeout chặn 1 lần gọi gpg treo (pinentry chờ input, file dữ liệu
// bất thường...) giữ goroutine per-connection (server.go) sống vô thời hạn —
// verify 1 file nhỏ bình thường chỉ mất mili giây, 30s đã rất dư dả.
const gpgVerifyTimeout = 30 * time.Second

// verifyBundleSignature xác thực content.tar.gz trong
// <signedContentDir>/<remediationRef>/ bằng GPG — tái dùng ĐÚNG cơ chế
// scripts/content-signing/lib-gpg-fingerprint.sh:verified_signer_fingerprint
// (gpg --status-fd 1 --verify, parse dòng "[GNUPG:] VALIDSIG <fingerprint>"
// máy đọc được thay vì grep chuỗi text tiếng Anh dễ vỡ khi đổi ngôn ngữ/
// version gpg). Không tự chế crypto — chỉ shell ra gpg đã cài sẵn, đúng
// nguyên tắc mục 8 architecture-proposal.md ("không tự chế crypto/IAM").
//
// trustedFingerprint PHẢI do caller truyền vào (cấu hình out-of-band của
// Executor) — KHÔNG đọc fingerprint tin cậy từ chính bundle đang verify,
// cùng nguyên tắc scripts/content-signing/verify.sh.
//
// TRẢ VỀ dataFile ĐÃ MỞ (đã seek về đầu) khi verify thành công — caller
// (execute.go:executeRemediation) BẮT BUỘC dùng ĐÚNG file handle này để
// giải nén (extractBundleFromReader), KHÔNG được tự os.Open lại theo path.
// Lý do (phát hiện qua rà soát đối kháng, không phải lý thuyết suông):
// signedContentDir CHÍNH LÀ thư mục cache Reporter ghi vào
// (AGENT_CONTENT_CACHE_DIR == EXECUTOR_SIGNED_CONTENT_DIR, cùng giá trị mặc
// định "/var/cache/hardening-agent/content" ở apps/agent/main.go và
// apps/agent/executor/main.go) — Reporter là thành phần lộ ra mạng, kém tin
// cậy hơn Executor. Nếu verify (đọc file lần 1) và extract (đọc file lần 2,
// mở lại theo PATH) là 2 lần mở độc lập, Reporter (bị chiếm quyền) có thể
// ghi đè content.tar.gz bằng writeFileAtomic (rename tức thời) ĐÚNG vào
// khoảng hở giữa 2 lần mở đó — Executor (chạy ROOT) sẽ giải nén+chạy nội
// dung CHƯA TỪNG được GPG xác thực, trong khi kết quả vẫn báo Verified=true.
// Mở file ĐÚNG 1 LẦN rồi tái dùng cùng *os.File cho cả 2 bước loại bỏ hoàn
// toàn cửa sổ TOCTOU này — rename() không ảnh hưởng tới fd đã mở trước đó
// (Linux/POSIX: fd tham chiếu inode, không tham chiếu path), nên nội dung
// GPG vừa xác thực chắc chắn là ĐÚNG NGUYÊN VẸN byte được giải nén sau đó.
func verifyBundleSignature(signedContentDir, remediationRef, trustedFingerprint string) (string, *os.File, error) {
	return verifyBundleSignatureWithTimeout(signedContentDir, remediationRef, trustedFingerprint, gpgVerifyTimeout)
}

// verifyBundleSignatureWithTimeout tách timeout ra tham số để test được
// đường timeout nhanh (test không thể "ghi đè" 1 package const) — production
// code chỉ gọi qua verifyBundleSignature ở trên, luôn dùng gpgVerifyTimeout.
func verifyBundleSignatureWithTimeout(signedContentDir, remediationRef, trustedFingerprint string, timeout time.Duration) (string, *os.File, error) {
	if remediationRef == "" {
		return "", nil, fmt.Errorf("thiếu remediation_ref")
	}
	// remediationRef đến thẳng từ job envelope qua Unix socket — KHÔNG đáng
	// tin. filepath.Join tự Clean() và resolve ".." nên
	// filepath.Join(signedContentDir, "../../etc") có thể thoát HẲN ra
	// ngoài signedContentDir (phát hiện qua rà soát bảo mật — chưa có
	// Reporter thật gọi tới socket này nên chưa khai thác được TRONG HỆ
	// THỐNG HIỆN TẠI, nhưng đây là lỗ hổng path traversal thật một khi có
	// caller thật, phải chặn từ bây giờ thay vì để lại làm "bom nổ chậm").
	// Chặn 2 lớp độc lập, không chỉ dựa vào 1 cách kiểm tra duy nhất:
	//   1. Bundle name hợp lệ (đúng quy ước scripts/content-signing/*.sh:
	//      "<name>-<timestamp>") không bao giờ cần chứa dấu phân cách
	//      đường dẫn hay "..".
	//   2. Containment check: đường dẫn SAU KHI Clean() vẫn phải nằm trong
	//      signedContentDir, phòng trường hợp check #1 có lỗ hổng chưa
	//      lường hết.
	if strings.ContainsAny(remediationRef, `/\`) || strings.Contains(remediationRef, "..") {
		return "", nil, fmt.Errorf("remediation_ref không hợp lệ (không được chứa dấu phân cách đường dẫn hoặc \"..\")")
	}
	bundleDir := filepath.Join(signedContentDir, remediationRef)
	signedContentDirClean := filepath.Clean(signedContentDir)
	if bundleDir != signedContentDirClean && !strings.HasPrefix(bundleDir, signedContentDirClean+string(filepath.Separator)) {
		return "", nil, fmt.Errorf("remediation_ref thoát ra ngoài thư mục nội dung đã ký")
	}
	dataPath := filepath.Join(bundleDir, "content.tar.gz")
	sigFile := filepath.Join(bundleDir, "content.tar.gz.sig")

	// Mở content.tar.gz ĐÚNG 1 LẦN — fd này (không phải đường dẫn) sẽ là
	// nguồn dữ liệu DUY NHẤT cho cả gpg (qua stdin) lẫn giải nén sau đó (xem
	// docstring hàm trên). Đóng lại ngay nếu bất kỳ bước nào sau đây thất bại
	// (chỉ trả file mở về caller khi verify thành công tuyệt đối).
	dataFile, err := os.Open(dataPath)
	if err != nil {
		return "", nil, fmt.Errorf("mở content.tar.gz thất bại cho remediation_ref=%q: %w", remediationRef, err)
	}

	// Lỗi thực thi gpg (file thiếu, sig hỏng, treo quá timeout...) không cần
	// phân biệt riêng — mọi trường hợp không tìm được dòng VALIDSIG hợp lệ
	// đều bị từ chối như nhau ở bước kiểm tra bên dưới (đúng tinh thần "chữ
	// ký không hợp lệ hoặc không verify được" của verify.sh).
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// "-" (data từ stdin) THAY CHO đường dẫn dataFile — gpg đọc đúng byte của
	// fd đã mở ở trên, không tự mở lại content.tar.gz theo path lần thứ 2.
	cmd := exec.CommandContext(ctx, "gpg", "--status-fd", "1", "--verify", sigFile, "-")
	cmd.Stdin = dataFile
	// cmd.Output() bắt buộc dùng pipe (goroutine copy) cho cả stdout/stderr —
	// exec.CommandContext mặc định chỉ Kill() đúng 1 tiến trình gpg khi hết
	// timeout; nếu gpg tự fork con (gpg-agent, dirmngr...), con đó vẫn giữ
	// đầu ghi pipe mở sau khi gpg cha bị kill, khiến Output() TREO tới khi
	// con tự thoát — bỏ qua timeout hoàn toàn (cùng lỗi + cách sửa đã xác
	// nhận bằng thực nghiệm cho apps/agent/scan.go). Đặt process group riêng
	// + kill cả group khi Cancel.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	out, _ := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		dataFile.Close()
		return "", nil, fmt.Errorf("gpg verify vượt timeout %s cho remediation_ref=%q", timeout, remediationRef)
	}

	fingerprint := parseValidSigFingerprint(string(out))
	if fingerprint == "" {
		dataFile.Close()
		return "", nil, fmt.Errorf("chữ ký không hợp lệ hoặc không verify được cho remediation_ref=%q", remediationRef)
	}
	if fingerprint != trustedFingerprint {
		dataFile.Close()
		return fingerprint, nil, fmt.Errorf("nội dung được ký bởi %s, không khớp fingerprint tin cậy %s", fingerprint, trustedFingerprint)
	}
	// Seek về đầu — gpg (qua stdin) đã đọc hết tới EOF, caller cần đọc lại
	// TỪ ĐẦU để giải nén đúng nguyên vẹn cùng byte vừa được xác thực.
	if _, err := dataFile.Seek(0, io.SeekStart); err != nil {
		dataFile.Close()
		return "", nil, fmt.Errorf("seek lại content.tar.gz sau verify thất bại: %w", err)
	}
	return fingerprint, dataFile, nil
}

func parseValidSigFingerprint(gpgStatusOutput string) string {
	scanner := bufio.NewScanner(strings.NewReader(gpgStatusOutput))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Định dạng: "[GNUPG:] VALIDSIG <fingerprint> <ngày ký> ...".
		if len(fields) >= 3 && fields[0] == "[GNUPG:]" && fields[1] == "VALIDSIG" {
			return fields[2]
		}
	}
	return ""
}
