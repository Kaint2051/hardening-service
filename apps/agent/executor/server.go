package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

type jobEnvelope struct {
	// Kind chọn nhánh xử lý ở handleConn — "" (rỗng, mặc định) = remediate
	// (tương thích ngược: Reporter cũ chưa biết field này vẫn gửi được job
	// remediate như trước), "restore" = khôi phục backup cục bộ (xem
	// execute.go:executeRestore) — KHÔNG qua đường verify GPG như remediation
	// bundle (xem docstring executeRestore để biết vì sao vẫn an toàn tương
	// đương đường SSH restore.sh hiện có).
	Kind           string `json:"kind,omitempty"`
	ControlID      string `json:"control_id"`
	RemediationRef string `json:"remediation_ref"`
	// DryRun chọn `ansible-playbook --check --diff` (không đổi gì trên máy,
	// chỉ xem trước) hay apply thật — xem execute.go:executeRemediation.
	DryRun bool `json:"dry_run"`
	// BackupTarB64 CHỈ dùng khi Kind=="restore" — nội dung backup base64 lấy
	// từ Job remediate-apply gốc (app/jobs.py:run_restore).
	BackupTarB64 string `json:"backup_tar_b64,omitempty"`
}

// executionResult thay thế verifyResult trước đây — giờ còn báo cáo kết quả
// THỰC THI remediation (Active Response), không chỉ kết quả verify chữ ký.
// Field/tên JSON PHẢI khớp đúng hợp đồng giao thức Reporter<->Executor (mục
// C tài liệu thiết kế) — Reporter (caller thật) parse đúng các tên này.
type executionResult struct {
	Verified          bool   `json:"verified"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	Reason            string `json:"reason,omitempty"`
	// Executed KHÔNG có omitempty (khác các field bên dưới) — false là giá
	// trị có ý nghĩa cần luôn xuất hiện tường minh trong JSON (vd trường hợp
	// verify thất bại: {"verified":false,...,"executed":false}), không phải
	// giá trị "rỗng" nên bỏ qua.
	Executed     bool   `json:"executed"`
	ExitCode     int    `json:"exit_code,omitempty"`
	DiffOutput   string `json:"diff_output,omitempty"`
	BackupTarB64 string `json:"backup_tar_b64,omitempty"`
	LogTail      string `json:"log_tail,omitempty"`
}

// serve lắng nghe Unix socket, mỗi kết nối = đúng 1 job envelope vào + 1
// executionResult ra rồi đóng — không có protocol dài hạn, không cần thiết
// cho tần suất job remediate (thấp) so với heartbeat/scan.
func serve(cfg executorConfig) error {
	// Bind-then-rename: Listen() vào 1 đường dẫn TẠM, siết ownership/quyền
	// trên đường dẫn tạm đó, rồi os.Rename() đè lên đường dẫn thật. Đường
	// dẫn thật (cfg.socketPath) vì vậy không bao giờ tồn tại trên filesystem
	// với quyền mặc định (umask hiện hành, thường lỏng hơn 0660) dù chỉ
	// trong khoảnh khắc ngắn — đóng HẲN cửa sổ TOCTOU giữa Listen và Chmod
	// của cách làm cũ (xem README mục "Mô hình quyền socket", trước đây
	// chấp nhận làm gap đã biết vì cách sửa triệt để duy nhất lúc đó —
	// syscall.Umask() — có tác dụng phụ toàn tiến trình). os.Rename trong
	// cùng filesystem là atomic theo POSIX, và rename() tự thay thế file cũ
	// tại đích nếu có nên KHÔNG cần os.Remove(cfg.socketPath) trước.
	tmpSocketPath := cfg.socketPath + ".tmp"
	// Chỉ đường dẫn TẠM có thể còn sót lại nếu process trước bị kill giữa
	// Listen và Rename (không tự dọn khi crash) — net.Listen từ chối bind
	// nếu file đã tồn tại.
	os.Remove(tmpSocketPath)

	// net.Listen("unix", ...) tạo file socket với quyền mặc định theo UMASK
	// TIẾN TRÌNH tại thời điểm gọi — nếu ambient umask lỏng (vd 022, không
	// phải 0077), đường dẫn TẠM có 1 khoảnh khắc world-readable/writable
	// trước khi os.Chown/os.Chmod bên dưới siết lại, dù đường dẫn THẬT
	// (cfg.socketPath) không bao giờ lộ ra khoảnh khắc đó (bind-then-rename
	// đã xử lý đúng phần đó). Trước đây an toàn của cửa sổ tạm này hoàn toàn
	// dựa vào `UMask=0077` trong hardening-executor.service — 1 phụ thuộc
	// NGOÀI code, không phải bất biến code tự đảm bảo (phát hiện qua rà soát
	// đối kháng). Siết umask CHỈ trong đúng khoảnh khắc gọi Listen rồi khôi
	// phục NGAY — an toàn ở đây (khác quan ngại umask trước đó về subprocess
	// gpg đang chạy song song) vì serve() chạy ĐƠN LUỒNG lúc khởi động,
	// TRƯỚC vòng lặp Accept() — chưa có goroutine handleConn/subprocess gpg
	// nào tồn tại có thể bị ảnh hưởng bởi umask toàn tiến trình trong
	// khoảnh khắc rất ngắn này.
	oldUmask := syscall.Umask(0177)
	ln, err := net.Listen("unix", tmpSocketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		return err
	}

	// Group dùng chung để Reporter (user quyền tối thiểu, khác user với
	// Executor) nối được vào socket này mà user khác trên máy thì không.
	// PHẢI đã tồn tại từ trước (provisioning tạo group + thêm Reporter vào
	// group đó) — từ chối chạy thay vì âm thầm rơi về ownership mặc định
	// nếu group chưa tồn tại, cùng nguyên tắc "từ chối nếu thiếu cấu hình
	// out-of-band" như EXECUTOR_TRUSTED_SIGNER_FINGERPRINT ở main.go.
	group, err := user.LookupGroup(cfg.socketGroup)
	if err != nil {
		ln.Close()
		os.Remove(tmpSocketPath)
		return fmt.Errorf("không tìm thấy group %q để gán quyền socket (PHẢI được tạo sẵn qua provisioning, Executor không tự tạo group): %w", cfg.socketGroup, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		ln.Close()
		os.Remove(tmpSocketPath)
		return fmt.Errorf("gid %q của group %q không phải số hợp lệ: %w", group.Gid, cfg.socketGroup, err)
	}
	// uid -1 nghĩa là giữ nguyên uid hiện tại (root, chạy chính Executor) —
	// chỉ đổi group.
	if err := os.Chown(tmpSocketPath, -1, gid); err != nil {
		ln.Close()
		os.Remove(tmpSocketPath)
		return fmt.Errorf("chown socket tạm về group %q thất bại: %w", cfg.socketGroup, err)
	}
	// 0660: chủ sở hữu (Executor, root) + group (Reporter) đọc/ghi được,
	// user khác trên máy thì không — thay cho 0600 chỉ-chủ-sở-hữu trước đây.
	if err := os.Chmod(tmpSocketPath, 0660); err != nil {
		ln.Close()
		os.Remove(tmpSocketPath)
		return fmt.Errorf("chmod socket tạm thất bại: %w", err)
	}
	if err := os.Rename(tmpSocketPath, cfg.socketPath); err != nil {
		ln.Close()
		os.Remove(tmpSocketPath)
		return fmt.Errorf("rename socket tạm đè lên đường dẫn thật thất bại: %w", err)
	}
	defer ln.Close()

	log.Printf("executor lắng nghe tại %s (group=%s, 0660) — verify chữ ký RỒI thực thi ansible-playbook cục bộ (Active Response, chạy quyền root)", cfg.socketPath, cfg.socketGroup)

	// acceptRetryDelay chặn Accept() spin CPU 100% trong 1 vòng log liên tục
	// nếu lỗi accept LẶP LẠI (vd cạn file descriptor) — cùng nguyên tắc
	// backoff-có-trần net/http tự dùng cho accept loop của chính nó. Reset về
	// 0 ngay khi accept thành công, không cộng dồn qua các lần thành công
	// xen giữa 2 lần lỗi không liên quan.
	var acceptRetryDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if acceptRetryDelay == 0 {
				acceptRetryDelay = 5 * time.Millisecond
			} else {
				acceptRetryDelay *= 2
			}
			if cap := time.Second; acceptRetryDelay > cap {
				acceptRetryDelay = cap
			}
			log.Printf("accept lỗi (thử lại sau %s): %v", acceptRetryDelay, err)
			time.Sleep(acceptRetryDelay)
			continue
		}
		acceptRetryDelay = 0
		go handleConn(conn, cfg)
	}
}

// connIOTimeout chặn 1 kết nối treo vô thời hạn (bên gửi gửi dở dang rồi im
// lặng, hoặc không bao giờ đọc phản hồi) chiếm goroutine mãi mãi — cộng dư
// biên độ cho gpgVerifyTimeout + remediationTimeout (thời gian
// executeRemediation có thể chạy thật) cùng thời gian mã hoá/giải mã JSON
// (không đáng kể). Reporter (bên gọi) đã tự đặt deadline tương tự phía nó
// (remediate.go:executorIOTimeout) — đây là PHÍA NGƯỢC LẠI, chạy quyền root,
// càng cần tự bảo vệ, không phụ thuộc client cư xử đúng (Reporter là nửa lộ
// ra mạng, giả định có thể bị chiếm quyền, theo đúng mô hình tách 2 tiến
// trình — xem README mục tách Reporter/Executor).
func connIOTimeout(cfg executorConfig) time.Duration {
	return cfg.remediationTimeout + gpgVerifyTimeout + 30*time.Second
}

func handleConn(conn net.Conn, cfg executorConfig) {
	defer conn.Close()
	// 1 panic ở BẤT KỲ đâu trong executeRemediation (hoặc chính hàm này) sẽ
	// crash TOÀN BỘ tiến trình Executor nếu không recover — cùng lý do
	// Reporter có runProtected() (../main.go) cho các vòng lặp của nó, áp
	// dụng CÀNG QUAN TRỌNG hơn ở đây: Executor chạy quyền root và xử lý
	// NHIỀU kết nối đồng thời (mỗi kết nối 1 goroutine riêng qua serve()), 1
	// job lỗi không được phép làm rớt các job khác đang thực thi song song.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("handleConn panic (đã recover, KHÔNG crash tiến trình): %v", r)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(connIOTimeout(cfg))); err != nil {
		log.Printf("đặt deadline cho kết nối thất bại: %v", err)
		return
	}

	var env jobEnvelope
	if err := json.NewDecoder(conn).Decode(&env); err != nil {
		json.NewEncoder(conn).Encode(executionResult{Verified: false, Reason: "envelope không phải JSON hợp lệ"})
		return
	}

	if env.Kind == "restore" {
		result := executeRestore(cfg, env)
		json.NewEncoder(conn).Encode(result)
		if !result.Executed {
			log.Printf("restore THẤT BẠI: %s", result.Reason)
			return
		}
		log.Printf("restore thực thi xong: exit_code=%d", result.ExitCode)
		return
	}

	// executeRemediation tự verify chữ ký TRƯỚC (gọi lại verifyBundleSignature
	// có sẵn) — nếu verify thất bại, trả về Verified:false/Executed:false mà
	// KHÔNG extract/chạy gì (xem execute.go), giữ nguyên hành vi an toàn cũ.
	result := executeRemediation(cfg, env)
	json.NewEncoder(conn).Encode(result)
	if !result.Verified {
		log.Printf("job control_id=%s remediation_ref=%s TỪ CHỐI: %s", env.ControlID, env.RemediationRef, result.Reason)
		return
	}
	if !result.Executed {
		log.Printf("job control_id=%s remediation_ref=%s verify OK (ký bởi %s) nhưng THỰC THI THẤT BẠI: %s", env.ControlID, env.RemediationRef, result.SignerFingerprint, result.Reason)
		return
	}
	log.Printf("job control_id=%s remediation_ref=%s dry_run=%v thực thi xong (ký bởi %s): exit_code=%d", env.ControlID, env.RemediationRef, env.DryRun, result.SignerFingerprint, result.ExitCode)
}
