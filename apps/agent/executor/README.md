# Executor (Active Response — chạy quyền root)

Tiến trình **riêng biệt** với Reporter (`../`) — mục 4.3
`docs/architecture-proposal.md`: tách 2 tiến trình trên mỗi máy để giảm blast
radius nếu Reporter (lộ ra mạng) bị tấn công. Executor chỉ nhận lệnh qua Unix
socket nội bộ, không mở port mạng nào.

**Active Response đã bật**: sau khi verify chữ ký GPG của bundle remediation
thành công, Executor THỰC SỰ giải nén bundle và chạy `ansible-playbook` cục
bộ trên chính máy đích — không còn chỉ verify-rồi-dừng như các pass trước.

## Chạy quyền root

Executor chạy **ROOT HOÀN TOÀN** (`User=root` trong `hardening-executor.service`),
**không phải** 1 capability set thu hẹp. Lý do: nội dung remediation là 1
playbook Ansible tuỳ ý nằm trong bundle đã ký — phạm vi hành động của nó
KHÔNG cố định trước (có thể đổi cấu hình SSH, PAM, sysctl, quyền file, khởi
động lại service, cài/gỡ gói...), nên không tồn tại 1 tập capability Linux cố
định nào vừa đủ mà không thừa cho MỌI playbook hợp lệ có thể có. Cố nén nhỏ
capability set trong tình huống này chỉ tạo cảm giác an toàn giả, trong khi
lớp kiểm soát THẬT là: **Executor từ chối chạy bất kỳ bundle nào không mang
chữ ký GPG hợp lệ từ đúng fingerprint tin cậy đã cấu hình out-of-band**
(`verify.go:verifyBundleSignature`) — ai kiểm soát được quy trình ký bundle
(`scripts/content-signing/`) mới kiểm soát được Executor làm gì, không phải
ai có quyền gọi socket.

Đánh đổi được ghi lại đầy đủ, không phải bỏ sót: xem mục 4.3/8
`docs/architecture-proposal.md` (Active Response "không nhận shell command
tự do — chỉ nhận `control_id` + `remediation_ref` đã có trong Control
Registry", và rủi ro Active Response là mốc cao nhất, chỉ bật sau pentest
riêng).

## Luồng xử lý 1 job

1. Reporter (`../`) claim 1 job remediate qua Orchestrator (relay qua Agent
   Manager), tải bundle đã ký về cache cục bộ dùng chung với Executor
   (`AGENT_CONTENT_CACHE_DIR` phía Reporter == `EXECUTOR_SIGNED_CONTENT_DIR`
   phía Executor — PHẢI cùng 1 path vật lý).
2. Reporter dial Unix socket của Executor, gửi đúng 1 job envelope
   `{"control_id", "remediation_ref", "dry_run"}`.
3. Executor `verifyBundleSignature` (tái dùng đúng cơ chế
   `scripts/content-signing/verify.sh`: `gpg --status-fd 1 --verify`, parse
   dòng `VALIDSIG` máy đọc được, không tự chế crypto).
   - **Verify thất bại** → trả `{"verified":false,"reason":"...","executed":false}`
     ngay, KHÔNG extract/chạy bất kỳ gì (`execute.go:executeRemediation`).
   - **Verify thành công** → giải nén `content.tar.gz` (`archive/tar` +
     `compress/gzip` CHUẨN của Go, không shell ra `tar` cho bước này — chặn
     zip-slip 2 lớp + cap tổng dung lượng giải nén chống zip-bomb, xem
     `execute.go:extractBundle`) vào 1 thư mục tạm, tìm `playbook.yml`.
4. Nếu `dry_run=true`: chạy `ansible-playbook -i localhost, -c local --check
   --diff playbook.yml` — KHÔNG đổi gì trên máy, KHÔNG backup.
5. Nếu `dry_run=false` (apply thật): **backup cấu hình liên quan TRƯỚC**
   (`captureBackup` — `tar czf -` danh sách path cố định, đồng bộ tay với
   `apps/execution-env/remediate.sh`, nguyên tắc cốt lõi #7 "rollback/backup
   được tạo TRƯỚC khi remediate thật"), RỒI mới chạy
   `ansible-playbook -i localhost, -c local playbook.yml`.
6. Trả `executionResult` đầy đủ (`exit_code`, `diff_output` hoặc
   `backup_tar_b64` tuỳ `dry_run`, `log_tail`) cho Reporter qua cùng kết nối,
   Reporter báo cáo tiếp lên Orchestrator qua
   `POST /internal/agent/remediate-result`.

Toàn bộ bước 4-6 (KHÔNG tính verify chữ ký, có timeout riêng 30s cố định)
nằm trong 1 `context.WithTimeout(EXECUTOR_REMEDIATE_TIMEOUT)`.

## Cấu hình (env)

- `EXECUTOR_SOCKET_PATH` (mặc định `/run/hardening-agent/executor.sock`)
- `EXECUTOR_SIGNED_CONTENT_DIR` (mặc định `/var/cache/hardening-agent/content`
  — PHẢI trỏ CÙNG path vật lý với `AGENT_CONTENT_CACHE_DIR` phía Reporter,
  xem `../provision.sh` tạo sẵn thư mục này với owner/mode đúng)
- `EXECUTOR_TRUSTED_SIGNER_FINGERPRINT` (**bắt buộc**, không có default —
  Executor từ chối chạy nếu thiếu; không đọc fingerprint tin cậy từ chính
  bundle đang verify, cùng nguyên tắc `scripts/content-signing/README.md`)
- `EXECUTOR_SOCKET_GROUP` (mặc định `hardening-agent`) — group được gán làm
  chủ nhóm (group owner) của socket, xem mục quyền socket bên dưới. Group
  này **PHẢI được tạo sẵn** (qua `../provision.sh`) trước khi khởi động
  Executor — Executor từ chối chạy (`serve()` trả lỗi) nếu group không tồn
  tại, không tự tạo group hay âm thầm rơi về ownership mặc định.
- `EXECUTOR_REMEDIATE_TIMEOUT` (Duration, mặc định `300s`) — trần thời gian
  cho 1 lần backup + chạy `ansible-playbook` (không tính verify chữ ký).
- `EXECUTOR_ANSIBLE_BINARY` (mặc định `ansible-playbook`) — đường dẫn/tên
  binary `ansible-playbook`, cho phép trỏ tới bản cài trong venv riêng.
  Executor `exec.LookPath` giá trị này lúc khởi động, `log.Fatalf` rõ ràng
  nếu không tìm thấy — **ansible-core giờ là dependency bắt buộc** trên host
  chạy Executor (khác pass verify-only trước đây, chỉ cần `gpg`).

## Build

```
./build.sh   # ra file ./executor (linux/amd64, static)
```

## Mô hình quyền socket

Bài toán "Reporter (user quyền tối thiểu) và Executor (user root) là 2 user
khác nhau, làm sao Reporter nối được vào socket của Executor mà user khác
trên máy thì không" giải quyết bằng 1 group dùng chung, mặc định
`hardening-agent` (cấu hình qua `EXECUTOR_SOCKET_GROUP`) — Reporter chạy dưới
user thuộc group đó, socket `0660` group-owned.

Cơ chế tạo socket (`server.go:serve()`) dùng **bind-then-rename** thay vì
Listen thẳng vào đường dẫn thật rồi Chmod sau:

1. `net.Listen("unix", socketPath+".tmp")` — bind vào đường dẫn TẠM, bọc
   `syscall.Umask(0177)` chỉ đúng lệnh Listen để đường dẫn TẠM cũng không lộ
   quyền mặc định dù chỉ 1 khoảnh khắc.
2. `os/user.LookupGroup(socketGroup)` tra gid — từ chối chạy nếu group chưa
   tồn tại.
3. `os.Chown(tmp, -1, gid)` + `os.Chmod(tmp, 0660)` trên đường dẫn TẠM.
4. `os.Rename(tmp, socketPath)` — atomic theo POSIX, đè lên đường dẫn thật.

Nhờ vậy đường dẫn thật (`socketPath`) không bao giờ tồn tại trên filesystem
với quyền mặc định của umask dù chỉ trong khoảnh khắc ngắn.

## Triển khai qua systemd

1. Chạy `../provision.sh` **1 lần** bằng root trên máy đích — tạo group dùng
   chung `hardening-agent`, user `hardening-agent` (Reporter), thư mục
   `/etc/hardening-agent` (state) và `/var/cache/hardening-agent/content`
   (cache bundle dùng chung Reporter/Executor), và cảnh báo (không fail) nếu
   thiếu `ansible-playbook` trong `PATH`. Executor giờ chạy `User=root` nên
   KHÔNG cần user hệ thống riêng cho nó nữa (khác pass trước, có
   `hardening-executor` — user đó không còn dùng nếu tạo mới, có thể để lại
   không xoá, không gây hại).
2. Cài `ansible-core` trên máy đích nếu chưa có (`apt install ansible-core`/
   `dnf install ansible-core`/tương đương) — Executor `log.Fatalf` ngay lúc
   khởi động nếu thiếu.
3. Tạo `/etc/hardening-agent/executor.env` (**KHÔNG commit vào git**) với ít
   nhất `EXECUTOR_TRUSTED_SIGNER_FINGERPRINT=<fingerprint GPG tin cậy>` (có
   thể thêm các biến khác ở mục "Cấu hình" nếu cần khác mặc định) — file này
   được systemd đọc bằng quyền root qua `EnvironmentFile=` TRƯỚC khi fork
   tiến trình Executor.
4. Copy binary đã build (`./build.sh`) và `hardening-executor.service` lên
   máy đích, ví dụ `/opt/hardening-agent/executor/executor` và
   `/etc/systemd/system/hardening-executor.service` (sửa `ExecStart=` trong
   unit nếu deploy vào đường dẫn khác).
5. `systemctl daemon-reload && systemctl enable --now hardening-executor.service`
   — log xem qua `journalctl -u hardening-executor -f`.

Unit chạy `User=root`, `Group=hardening-agent` (để tự chown socket), giữ lại
những hardening directive KHÔNG mâu thuẫn với việc ghi `/etc/*`/reload
`/proc/sys` mà remediation cần làm (`NoNewPrivileges=true`, `PrivateTmp=true`,
`PrivateDevices=true`, `ProtectKernelModules=true`, `ProtectControlGroups=true`,
`RestrictSUIDSGID=true`, `RestrictNamespaces=true`, `LockPersonality=true`,
`UMask=0077`) — xem comment trong chính file `hardening-executor.service` để
biết lý do từng directive bị GỠ (`ProtectSystem=strict`, `ProtectHome=true`,
`ProtectKernelTunables=true`, `CapabilityBoundingSet=`/`AmbientCapabilities=`
rỗng). `Restart=on-failure` (5s) tự khởi động lại nếu crash.

## Việc CHƯA làm

- **Đã nối dây thật** (khác các bản trước của file này): Reporter
  (`../remediate.go`) giờ tự động claim/tải bundle/gọi socket này qua vòng lặp
  định kỳ (`AGENT_REMEDIATE_POLL_INTERVAL`) — không còn là scaffold độc lập
  chưa có caller.
- "1-click restore" (`app/jobs.py:run_restore`) không cần nối dây riêng cho
  đường agent-based: endpoint này chỉ cần 1 job `remediate-apply` đã
  `succeeded` có `backup_tar_b64` trong `result_summary` — không phân biệt
  job đó tới từ SSH agentless hay từ Agent (cả 2 ghi cùng shape vào bảng
  `jobs`), và luôn restore lại qua đường SSH sẵn có
  (`apps/execution-env/restore.sh`), không qua Agent.

## Đã rà soát bảo mật

- Path traversal qua `remediation_ref` (2 lớp: từ chối dấu phân cách đường
  dẫn/`".."`, + containment-check đường dẫn sau `Clean()`) — xem `verify.go`.
- Zip-slip + zip-bomb lúc giải nén bundle (2 lớp containment-check cho tên
  entry VÀ target của symlink/hardlink, cap tổng dung lượng giải nén) — xem
  `execute.go:extractBundle`, test trong `execute_test.go`.
- Timeout + kill cả process-group (không chỉ 1 tiến trình) cho MỌI subprocess
  Executor fork ra (`gpg`, `ansible-playbook`, `tar` backup) — chặn treo vô
  thời hạn nếu subprocess tự fork con giữ pipe mở, cùng pattern đã xác nhận
  bằng thực nghiệm ở `apps/agent/scan.go`.
