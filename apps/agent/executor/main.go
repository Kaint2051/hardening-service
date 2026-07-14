// Executor — tiến trình quyền root RIÊNG BIỆT với Reporter (mục 4.3
// architecture-proposal.md: "Tách 2 tiến trình trên mỗi máy... giảm blast
// radius nếu agent bị tấn công qua mạng — Reporter lộ ra mạng, Executor chỉ
// nhận lệnh qua Unix socket nội bộ"). Binary riêng (package main riêng thư
// mục này), KHÔNG chung tiến trình với Reporter (../), dù cùng module Go.
//
// Active Response ĐÃ BẬT: nhận job envelope {control_id, remediation_ref,
// dry_run} qua Unix socket, verify chữ ký GPG của bundle content-signing
// tương ứng (tái dùng ĐÚNG cơ chế scripts/content-signing/verify.sh —
// gpg --status-fd 1 --verify, parse dòng VALIDSIG máy đọc được, không tự chế
// crypto) — verify THẤT BẠI thì dừng ngay, không extract/chạy gì. Verify
// THÀNH CÔNG thì giải nén bundle (archive/tar/gzip chuẩn của Go, chặn
// zip-slip/zip-bomb — xem execute.go:extractBundle) rồi chạy
// `ansible-playbook` cục bộ (`-c local`, `--check --diff` nếu dry-run; backup
// cấu hình liên quan TRƯỚC khi apply thật — nguyên tắc cốt lõi #7). Chạy
// ROOT HOÀN TOÀN (không phải capability set thu hẹp) — nội dung remediation
// là 1 playbook Ansible tuỳ ý trong bundle đã ký, phạm vi hành động không cố
// định trước nên không có capability set cố định nào là "đủ mà không thừa"
// (mục 4.3/8 architecture-proposal.md: Active Response "không nhận shell
// command tự do", lớp kiểm soát chính là chữ ký GPG chứ không phải quyền hệ
// điều hành của Executor) — xem thêm README.md cùng thư mục mục "Chạy quyền
// root" và hardening-executor.service để biết đầy đủ lý do đánh đổi.
//
// Caller thật: Reporter (../) — sau khi claim 1 job remediate qua Orchestrator
// (POST /internal/agent/remediate-jobs/claim, relay qua Agent Manager) và tải
// bundle đã ký về cache cục bộ (AGENT_CONTENT_CACHE_DIR, PHẢI trỏ CÙNG path
// vật lý với EXECUTOR_SIGNED_CONTENT_DIR bên dưới), Reporter dial Unix socket
// này gửi đúng 1 job envelope, đọc executionResult, rồi báo cáo kết quả về
// Orchestrator qua POST /internal/agent/remediate-result.
package main

import (
	"log"
	"os"
	"os/exec"
	"time"
)

type executorConfig struct {
	socketPath         string
	signedContentDir   string
	trustedFingerprint string
	socketGroup        string
	// remediationTimeout bọc toàn bộ 1 lần thực thi remediation (backup +
	// ansible-playbook, KHÔNG tính bước verify chữ ký — verify có timeout
	// riêng 30s cố định, xem verify.go:gpgVerifyTimeout) — playbook Ansible
	// tuỳ ý có thể chạy lâu hơn nhiều so với gpg verify, 300s mặc định đã
	// tính dư cho hầu hết remediation 1 control.
	remediationTimeout time.Duration
	// ansibleBinary cho phép trỏ tới 1 bản ansible-playbook khác đường dẫn
	// PATH mặc định (vd cài qua venv riêng) — mặc định "ansible-playbook",
	// đủ dùng khi ansible-core cài qua package manager hệ thống.
	ansibleBinary string
}

func loadExecutorConfig() executorConfig {
	return executorConfig{
		socketPath: getenv("EXECUTOR_SOCKET_PATH", "/run/hardening-agent/executor.sock"),
		// Cùng path vật lý với AGENT_CONTENT_CACHE_DIR của Reporter (../
		// scan.go tải bundle về đây) — trước đây trỏ tới đường dẫn container
		// Orchestrator (vô nghĩa trên host chạy Executor thật), nay đổi sang
		// thư mục cache dùng chung Reporter (ghi qua group)/Executor (đọc, vô
		// điều kiện vì giờ chạy root).
		signedContentDir:   getenv("EXECUTOR_SIGNED_CONTENT_DIR", "/var/cache/hardening-agent/content"),
		trustedFingerprint: os.Getenv("EXECUTOR_TRUSTED_SIGNER_FINGERPRINT"),
		// Group dùng chung để Reporter (user quyền tối thiểu) nối được vào
		// socket của Executor (user root) mà user khác trên máy thì không —
		// xem server.go:serve() + README mục quyền socket. PHẢI đã tồn tại
		// từ trước (provisioning), Executor không tự tạo group.
		socketGroup:        getenv("EXECUTOR_SOCKET_GROUP", "hardening-agent"),
		remediationTimeout: getenvDuration("EXECUTOR_REMEDIATE_TIMEOUT", 300*time.Second),
		ansibleBinary:      getenv("EXECUTOR_ANSIBLE_BINARY", "ansible-playbook"),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("giá trị %s=%q không hợp lệ, dùng mặc định %s", key, v, def)
		return def
	}
	return d
}

func main() {
	cfg := loadExecutorConfig()
	// Không đọc fingerprint tin cậy từ chính bundle đang verify (đúng nguyên
	// tắc scripts/content-signing/README.md) — PHẢI cấu hình out-of-band,
	// từ chối chạy nếu thiếu thay vì fallback sang "tin mọi chữ ký".
	if cfg.trustedFingerprint == "" {
		log.Fatalf("thiếu EXECUTOR_TRUSTED_SIGNER_FINGERPRINT — Executor từ chối chạy nếu không biết trước fingerprint tin cậy")
	}
	// ansible-core giờ là dependency BẮT BUỘC trên host chạy Executor (khác
	// pass verify-only trước đây, không cần gì ngoài gpg) — từ chối chạy rõ
	// ràng ngay lúc khởi động thay vì để lỗi mù mờ "executable file not
	// found" lần đầu có job remediate thật.
	if _, err := exec.LookPath(cfg.ansibleBinary); err != nil {
		log.Fatalf("không tìm thấy %q trong PATH (EXECUTOR_ANSIBLE_BINARY=%q) — cài ansible-core trên host này trước khi bật Active Response: %v", cfg.ansibleBinary, cfg.ansibleBinary, err)
	}
	if err := serve(cfg); err != nil {
		log.Fatalf("executor dừng: %v", err)
	}
}
