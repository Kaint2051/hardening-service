# Agent (Reporter)

Binary Go chạy trên từng máy trong fleet (mục 4.3 `docs/architecture-proposal.md`).
Reporter chạy 5 vòng lặp độc lập sau khi enroll: heartbeat, scan OpenSCAP cục
bộ, FIM hash định kỳ, renew cert mTLS ở giữa chu kỳ hiệu lực (xem mục
"Renew cert" bên dưới), và poll/thực thi remediation job qua Executor (tính
năng Active Response, xem mục "Active Response" bên dưới). **Executor là 1
binary RIÊNG** (`./executor/`, không lẫn vào Reporter) — cố ý tách để không
lẫn "quyền tối thiểu" của Reporter với "quyền cao hơn" của Executor. Kill-switch
THẬT của Active Response nằm ở Orchestrator (`active_response_enabled`, mặc
định TẮT) — xem `./executor/README.md` để biết trạng thái Executor hiện tại.

## Chuẩn bị trước khi chạy (operator làm thủ công, out-of-band)

1. Tạo bootstrap token: `POST /hosts/{hostname}/agent-enrollment-tokens` trên
   Orchestrator (role operator/admin) — trả token 1 lần, TTL 5 phút.
2. Đặt 2 file lên máy đích, tại `/etc/hardening-agent/` (hoặc `AGENT_STATE_DIR`):
   - `enroll-token` — token vừa tạo (bí mật, dùng 1 lần, TTL ngắn).
   - `ca-root.crt` — root cert của step-ca (**không bí mật**, chỉ root KEY
     mới bí mật; lấy qua `docker compose exec step-ca cat certs/root_ca.crt`).
     Agent dùng file này để verify server cert của Agent Manager NGAY TỪ
     request đầu tiên — không có bước nào dùng `InsecureSkipVerify`.
3. Chạy binary (`./build.sh` để biên dịch, xem bên dưới), cấu hình qua env:
   - `AGENT_MANAGER_URL` (mặc định `https://localhost:8443`)
   - `AGENT_MANAGER_TLS_SERVERNAME` (mặc định `agent-manager` — phải khớp
     subject Orchestrator dùng để cấp cert cho Agent Manager)
   - `AGENT_HOSTNAME` (mặc định lấy hostname hệ thống — PHẢI khớp hostname
     đã tạo token ở bước 1 và hostname đã thêm vào Control Registry)
   - `AGENT_STATE_DIR` (mặc định `/etc/hardening-agent`)
   - `AGENT_HEARTBEAT_INTERVAL` (mặc định `60s`)
   - `AGENT_SCAN_INTERVAL` (mặc định `1h`), `AGENT_SCAP_PROFILE` (mặc định
     `xccdf_org.ssgproject.content_profile_cis_level1_server`, khớp entry
     `ubuntu2204-cis-level1-server` trong `jobs.py:SCAP_PROFILES` phía
     agentless), `AGENT_SCAP_DATASTREAM` (mặc định
     `/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml` — **máy đích
     phải tự cài sẵn gói `ssg-debderived` + `openscap-scanner`**, agent
     không tự cài, cùng yêu cầu như đường agentless hiện có).
   - `AGENT_FIM_INTERVAL` (mặc định `5m`), `AGENT_FIM_PATHS` (danh sách
     path phân cách dấu phẩy, mặc định `/etc/ssh/sshd_config,/etc/passwd,
     /etc/shadow`).
   - `AGENT_REMEDIATE_POLL_INTERVAL` (mặc định `15s`), `AGENT_CONTENT_CACHE_DIR`
     (mặc định `/var/cache/hardening-agent/content` — PHẢI trùng path vật lý
     với `EXECUTOR_SIGNED_CONTENT_DIR` phía Executor), `AGENT_EXECUTOR_SOCKET_PATH`
     (mặc định `/run/hardening-agent/executor.sock`, khớp `EXECUTOR_SOCKET_PATH`
     mặc định phía Executor) — xem mục "Active Response" bên dưới.

Sau khi enroll xong (cert lưu tại `agent.crt`/`agent.key` trong state dir),
token bị xoá ngay — chạy lại binary sau đó bỏ qua hẳn bước enroll.

## Scan OpenSCAP cục bộ

Chạy `oscap xccdf eval` NGAY trên máy (không qua SSH như đường agentless
hiện có), parse `results.xml` (bỏ qua notapplicable/error, chỉ giữ
pass/fail — cùng quy ước với `apps/execution-env/scan.sh`), POST
`result_summary` qua Agent Manager tới `/internal/agent/scan-result` —
Orchestrator ghi vào đúng bảng `jobs` có sẵn (`job_type="agent-scan"`,
`triggered_by="agent"`), cùng shape với job scan agentless nên UI/API đọc
được cả 2 nguồn như nhau.

## FIM (File Integrity Monitoring)

MVP hash-compare định kỳ (SHA-256), KHÔNG dùng `inotify` real-time (xem mục
4.3 tài liệu kiến trúc — nâng lên real-time là việc của giai đoạn sau nếu
cần). Agent không có state lưu qua lần restart — **lượt quét đầu tiên sau
mỗi lần khởi động luôn là baseline, không báo event nào**, chỉ các lượt sau
trong cùng vòng đời process mới so sánh và báo `created`/`modified`/
`deleted` qua `/internal/agent/fim-event`.

## Renew cert

Cert mTLS nhận lúc enroll có TTL cố định theo cấu hình provisioner step-ca.
Reporter tự renew ở **giữa chu kỳ hiệu lực** (`NotBefore +
(NotAfter-NotBefore)/2`, tính lại từ chính cert đang dùng ở mỗi vòng lặp —
KHÔNG hardcode 1 khoảng cố định, nên vẫn đúng nếu TTL provisioner đổi sau
này) bằng cách POST `{"hostname"}` qua Agent Manager tới `/renew` (relay
sang `/internal/agent/renew-cert` trên Orchestrator — danh tính agent đã
được chứng minh qua chính handshake mTLS của request này, không cần bootstrap
token dùng-1-lần như lúc enroll ban đầu). Cert/key mới nhận về được validate
(`tls.X509KeyPair`) TRƯỚC KHI ghi xuống đĩa, ghi ra file tạm rồi
`os.Rename` đè lên `agent.crt`/`agent.key`/`ca-root.crt` (atomic, mode
0600), sau đó hot-swap vào client HTTP đang chạy qua
`tls.Config.GetClientCertificate` — không downtime, không cần restart
process.

Renew lỗi (mạng, cert/key nhận về không hợp lệ, hoặc bị operator khoá — xem
dưới) chỉ log cảnh báo, Reporter tiếp tục dùng cert cũ (còn hiệu lực tới
`NotAfter`) và thử lại sau 1 phút — không crash, không fatal.

operator/admin có thể tạm khoá renew cho 1 host qua
`PATCH /hosts/{hostname}/agent-renewal` (role operator/admin, body
`{"blocked": true}`) — ví dụ khi host bị nghi ngờ chiếm quyền, chờ điều tra;
từ lúc đó agent renew sẽ nhận lỗi 403 và cert sẽ tự hết hạn theo TTL gốc.

## Active Response

Vòng lặp thứ 5 (`remediate.go`): mỗi `AGENT_REMEDIATE_POLL_INTERVAL`, Reporter
POST `{"hostname"}` tới `/remediate-jobs/claim` (Agent Manager relay). Không
có job đang chờ (204, hoặc kill-switch `active_response_enabled` phía
Orchestrator đang tắt) thì bỏ qua, không log ồn. Có job (200,
`{"job_id","control_id","remediation_ref","dry_run"}`):

1. **Cache bundle** (`ensureBundleCached`): nếu
   `<AGENT_CONTENT_CACHE_DIR>/<remediation_ref>/content.tar.gz` +
   `.sig` đã có sẵn (bundle bất biến theo tên ref), dùng luôn, KHÔNG gọi lại
   mạng. Nếu chưa, POST `/remediation-bundle`, giải mã base64 2 field
   response, ghi xuống cache qua `writeFileAtomic` (mode `0660`).
2. **Chuyển cho Executor**: dial `AGENT_EXECUTOR_SOCKET_PATH` (Unix socket),
   gửi `{"control_id","remediation_ref","dry_run"}`, đọc lại đúng 1
   `executionResult` (`{"verified","signer_fingerprint","reason","executed",
   "exit_code","diff_output","backup_tar_b64","log_tail"}`) rồi đóng kết nối.
3. **Báo kết quả**: POST `/remediate-result` với đầy đủ field (kể cả khi
   Executor từ chối verify chữ ký, dial socket lỗi, hay không phản hồi kịp —
   Reporter LUÔN báo lại 1 kết quả, không bao giờ để job kẹt "running" vĩnh
   viễn phía Orchestrator chỉ vì Executor chết/treo cục bộ).

Giới hạn `BACKUP_MAX_BYTES` cho `backup_tar_b64` là việc của Orchestrator
(`jobs.py`) — Reporter/Executor không tự cắt.

Thư mục cache (`AGENT_CONTENT_CACHE_DIR`) cần quyền ghi cho user Reporter
(`hardening-agent`) và quyền đọc cho Executor — xem `CacheDirectory=` trong
`hardening-agent.service` (mục "Triển khai qua systemd" bên dưới).

## Build

```
./build.sh   # ra file ./agent (linux/amd64, static, không cần Go trên host)
```

## Triển khai qua systemd (khuyến nghị cho môi trường thật)

1. Chạy 1 lần trên máy đích, bằng root: `./provision.sh` — tạo user hệ
   thống `hardening-agent` (Reporter, không login, không home), user
   `hardening-executor` (Executor, xem `executor/README.md`), group dùng
   chung `hardening-agent` (để Executor tự chown được socket cho Reporter
   kết nối), và thư mục `/etc/hardening-agent` (owner đúng, `chmod 0700`).
   Script idempotent — chạy lại an toàn, KHÔNG đụng cert/key/token đã có
   nếu máy này từng chạy Agent như process trần trước khi có systemd unit.
2. Hoàn tất mục "Chuẩn bị trước khi chạy" ở trên (đặt `enroll-token` +
   `ca-root.crt` vào `/etc/hardening-agent`, hoặc `AGENT_STATE_DIR`).
3. Copy binary đã build (`./build.sh`) và `hardening-agent.service` lên
   máy đích, ví dụ `/opt/hardening-agent/agent` và
   `/etc/systemd/system/hardening-agent.service` (sửa `ExecStart=` trong
   unit nếu deploy vào đường dẫn khác).
4. **Triển khai thật (Agent Manager KHÔNG chạy cùng máy)**: tạo
   `/etc/hardening-agent/agent.env` (unit đọc qua `EnvironmentFile=-...`,
   dấu `-` nghĩa là bỏ qua nếu file chưa có — mặc định
   `AGENT_MANAGER_URL=https://localhost:8443` chỉ đúng khi test trên cùng
   máy với Agent Manager) với ít nhất:
   ```
   AGENT_MANAGER_URL=https://<địa chỉ Agent Manager thật>:8443
   AGENT_HOSTNAME=<hostname đã đăng ký trong Host Registry>
   ```
   (`AGENT_HOSTNAME` mặc định lấy theo `os.Hostname()` của máy — chỉ cần đặt
   tường minh nếu khác tên đã đăng ký, hoặc muốn cố định thay vì phụ thuộc
   cấu hình DNS/hostname hệ thống.)

   **Cả `POST .../agent-install` (tự động) và `.../agent-install-script` (dán
   tay) đều TỰ ghi file này** nếu `settings.agent_manager_public_url` đã cấu
   hình (`.env`) — chỉ cần tạo tay theo hướng dẫn trên nếu KHÔNG dùng 1 trong
   2 endpoint này (vd chạy binary trần không qua script sinh sẵn). Thiếu biến
   này, Agent "cài xong" (service chạy, không lỗi) nhưng KHÔNG BAO GIỜ enroll
   được — lỗi âm thầm đã gặp thật (audit log có `agent_install_completed`
   nhưng không có `agent_enrolled`), xem `app/config.py:agent_manager_public_url`.
5. `systemctl daemon-reload && systemctl enable hardening-agent.service && systemctl restart hardening-agent.service`
   — dùng `restart` (không chỉ `enable --now`) để chắc chắn áp dụng binary/
   agent.env MỚI kể cả khi service đã chạy từ lần cài trước — log xem qua
   `journalctl -u hardening-agent -f`.

Unit chạy dưới user `hardening-agent` (không phải root), kèm bộ hardening
directive chuẩn (`ProtectSystem=strict`, `NoNewPrivileges=true`,
`CapabilityBoundingSet=` rỗng, `UMask=0077`...) — mở 2 ngoại lệ ghi:
`ReadWritePaths=/etc/hardening-agent` (Reporter cần ghi cert/key vào đó ngay
từ lần enroll đầu tiên, và ghi lại mỗi lần renew cert sau này — xem mục
"Renew cert" ở trên), và `CacheDirectory=hardening-agent` (systemd tự tạo +
chown `/var/cache/hardening-agent` mỗi lần start, khớp
`AGENT_CONTENT_CACHE_DIR` mặc định — xem mục "Active Response" ở trên).
`Restart=on-failure` (5s) tự khởi động lại nếu crash.

## Remote-deploy tự động (đóng gói bundle cho `POST /hosts/{hostname}/agent-install`)

Khác mục "Triển khai qua systemd" ở trên (operator tự SSH/scp/chạy tay, hoặc
dán script gộp sẵn từ `POST /hosts/{hostname}/agent-install-script`),
`POST /hosts/{hostname}/agent-install` (xem `app/agents.py:trigger_agent_install`)
tự động hoá HOÀN TOÀN: Orchestrator tự SSH bằng cert ephemeral (host phải đã
`trust_deployed`/`migrated`), tự scp binary + provision.sh + 2 systemd unit,
tự chạy cài đặt — không cần operator thực thi gì trên máy đích.

Đổi lại, binary `agent`/`executor` (và provision.sh + 2 unit file) phải được
đóng gói thành **1 bundle đã ký** qua đúng quy trình 3 vai trò
(`scripts/content-signing/README.md`), vì `apps/execution-env/agent-install.sh`
verify chữ ký TRƯỚC khi đẩy bất cứ gì lên máy đích — không có ngoại lệ, cùng
nguyên tắc `remediate.sh` áp dụng cho remediation content.

### Đóng gói

```bash
./build.sh              # ra ./agent
./executor/build.sh     # ra ./executor/executor (xem executor/README.md)

mkdir -p /tmp/agent-bundle-payload
cp agent executor/executor provision.sh hardening-agent.service \
   executor/hardening-executor.service /tmp/agent-bundle-payload/
tar czf /tmp/agent-bundle.tar.gz -C /tmp/agent-bundle-payload .
```

**Bundle PHẢI chứa đúng 5 file này ở gốc** (không nằm trong thư mục con) —
`agent-install.sh` từ chối chạy nếu thiếu file nào sau khi giải nén:
`agent`, `executor`, `provision.sh`, `hardening-agent.service`,
`hardening-executor.service`.

### Ký (quy trình 3 vai trò — 3 người, 3 GPG key khác nhau)

```bash
# Puller (có thể dùng file:// cho artifact build cục bộ, không chỉ URL công khai)
scripts/content-signing/pull.sh "file:///tmp/agent-bundle.tar.gz" agent-v1

# Reviewer (máy khác, GPG key khác)
scripts/content-signing/review.sh staging/agent-v1-<timestamp>

# Signer (máy khác, GPG key khác)
scripts/content-signing/sign.sh reviewed/agent-v1-<timestamp>
```

Sau khi ký xong, set trong `.env` của Orchestrator:
```
AGENT_BUNDLE_REF=agent-v1-<timestamp>            # khớp đúng tên thư mục vừa tạo trong signed/
AGENT_BUNDLE_TRUSTED_FINGERPRINT=<fingerprint của Signer>
```
`AGENT_BUNDLE_TRUSTED_FINGERPRINT` CỐ Ý tách riêng khỏi
`CONTENT_SIGNING_TRUSTED_FINGERPRINT` (dùng cho remediation content) — đổi 1
trong 2 không làm hỏng verify của bên còn lại (xem app/config.py). Public key
của Signer cũng phải nằm trong `apps/execution-env/trusted-signer-pubkey.asc`
(gpg import được nhiều key cùng lúc từ 1 file — thêm vào, không cần thay thế
key remediation nếu đã có) rồi rebuild image:
```
docker build --build-arg INSTALL_REMEDIATION_ROLES=false \
  -t hardening-console-execution-env:latest ./apps/execution-env
docker compose up -d orchestrator
```

Ký bản agent mới (sau khi sửa code) lặp lại đúng quy trình trên với `name`
mới (vd `agent-v2`), rồi cập nhật lại `AGENT_BUNDLE_REF`.

## Việc CHƯA làm

- **Đã nối dây thật** (khác các bản trước của file này): 3 endpoint phía
  Orchestrator (`/remediate-jobs/claim`, `/remediation-bundle`,
  `/remediate-result`), route relay tương ứng phía Agent Manager, và Executor
  dùng đúng giao thức `executionResult` mới (không còn `verifyResult` cũ) đều
  đã tồn tại và có test pass — xem mục "Nối dây thật đường Active Response..."
  trong README gốc. Toàn bộ vòng lặp claim → cache bundle → gọi Executor →
  báo kết quả đã verify E2E thật trên lab server (dry-run + apply thật, four-eyes
  Tier 0/1). Kill-switch (`active_response_enabled` phía Orchestrator, mặc
  định TẮT) vẫn đang tắt chờ pentest riêng — không phải vì thiếu code.
- IO priority khi scan OpenSCAP chạy (`ionice`) — đã hạ CPU nice value
  (`syscall.Setpriority`, xem `scan.go:performLocalScan`) nhưng chưa có
  binding chuẩn cho `ioprio_set` trong Go, tự gọi raw syscall theo kiến trúc
  CPU cụ thể bị đánh giá rủi ro hơn vấn đề đang giải quyết (oscap thiên về
  CPU hơn IO) — chấp nhận đây là gap đã biết.
