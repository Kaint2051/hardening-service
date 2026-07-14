# Postgres — Backup/PITR (Giai đoạn 3, Phase 1/7 HA control-plane)

Giai đoạn 3 (`docs/architecture-proposal.md` mục 7) bắt đầu bằng việc lấp gap
lớn nhất hiện có: **Postgres trước đây không có bất kỳ backup/replication/PITR
nào** — mất volume `postgres-data` (hỏng đĩa, `docker volume rm` nhầm, VM
chết...) đồng nghĩa mất toàn bộ Control Registry/Audit Log/Jobs/Hosts, không
có đường phục hồi. Phase này thêm backup + Point-in-Time Recovery (PITR)
bằng [pgBackRest](https://pgbackrest.org/) — **chưa phải HA runtime** (chưa
có replica/standby, xem Phase 5 trong roadmap 7 phase ở
`docs/architecture-proposal.md`), chỉ là an toàn dữ liệu (RPO/RTO đo được,
không phải 0/∞ như trước).

## Vì sao không tách container riêng (sidecar)

pgBackRest cần đọc trực tiếp `PGDATA` (để `archive_command` copy từng WAL
segment lúc Postgres tạo ra) và cần chạy dưới user `postgres` để có quyền
đọc đúng file — cách đơn giản nhất ở quy mô 1 VM là cài thêm layer
`pgbackrest` (Alpine package) ngay vào chính image Postgres
(`infra/postgres/Dockerfile`), thay vì dựng 1 container riêng phải chia sẻ
`PGDATA` qua volume (thêm 1 lớp phức tạp không cần thiết ở bước này). Nếu
sau này tách sang VM riêng (Phase 3-4), pgBackRest vẫn chạy đúng cách này —
chỉ đổi `repo1-path`/`repo1-host` trong `pgbackrest.conf` để trỏ backup
sang máy khác.

## Cơ chế

- `wal_level=replica` + `archive_mode=on` + `archive_command=pgbackrest
  --stanza=hardening-console archive-push %p` (đặt qua `command:` của
  service `postgres` trong `docker-compose.yml`, KHÔNG sửa
  `postgresql.conf` gốc của image) — mỗi WAL segment (tối đa
  `archive_timeout=60s` một lần dù ít thay đổi) được đẩy liên tục vào repo
  pgBackRest ngay khi tạo ra. Đây là nguồn PITR **giữa 2 lần full backup**
  — không phải chỉ khôi phục được về đúng lúc backup gần nhất.
- `wal_level=replica` cũng là điều kiện bắt buộc cho streaming replication
  (Phase 5) — bật sẵn từ Phase 1 này để khỏi phải đổi lại/restart sau.
- Repo backup lưu ở volume Docker riêng `pgbackrest-repo` — **tạm cùng
  VM/Docker daemon với `postgres-data`** (chấp nhận được ở quy mô 1 VM hiện
  tại, KHÔNG bảo vệ được nếu mất CẢ VM, chỉ bảo vệ khỏi hỏng volume/lỗi
  logic/xoá nhầm). Di dời sang VM/host khác ở Phase 3-4 chỉ cần đổi
  `repo1-path`/`repo1-host` trong `pgbackrest.conf`.

## Lịch backup (MVP — chỉ full, chưa cần diff/incr)

`infra/postgres/backup.sh` chạy full backup mỗi lần gọi (tham số `diff` có
sẵn cho tương lai nếu dữ liệu lớn lên và full hàng ngày trở nên tốn thời
gian/dung lượng — chưa cần ở quy mô hiện tại). `repo1-retention-full=7`
(`pgbackrest.conf`) giữ 7 full gần nhất (~1 tuần nếu chạy hàng ngày).

**Cài cron trên VM host** (đơn giản hơn dựng thêm 1 container cron riêng ở
bước này — cân nhắc lại nếu Phase 3 chuyển sang Swarm, lúc đó "cron trên
host" theo từng node sẽ bất tiện hơn):

```cron
# /etc/cron.d/hardening-console-pg-backup — chạy 2h sáng, dưới user root
# (docker compose exec tự vào đúng container, backup.sh tự chạy pgbackrest
# dưới user postgres bên trong container qua -u postgres)
0 2 * * * root cd /opt/hardening-console && docker compose exec -T -u postgres postgres pgbackrest-backup.sh full >> /var/log/hardening-console-pg-backup.log 2>&1
```

Backup thủ công ngay: `docker compose exec -u postgres postgres pgbackrest-backup.sh full`.

## Restore drill (rehearsal PITR — bắt buộc chạy thử trước khi tin tưởng backup)

```bash
./infra/postgres/restore-drill.sh
```

Dựng 1 container Postgres **tạm** (service `postgres-restore-drill`, profile
riêng — không chạy cùng `docker compose up` mặc định), phục hồi từ CHÍNH
repo backup thật (đọc-chỉ) vào volume hoàn toàn riêng
(`postgres-restore-drill-data`), khởi động, in số dòng/`max_id` bảng
`audit_log` để đối chiếu bằng mắt với dữ liệu thật, rồi tự dọn sạch
container + volume tạm — **không đụng `postgres-data` thật ở bất kỳ bước
nào**. Script tự đo + in thời gian từ lúc bắt đầu tới lúc Postgres phục hồi
sẵn sàng — đây là RTO tham khảo thật, không phải số lý thuyết.

Nên chạy drill này **định kỳ** (vd hàng tháng) — backup "chưa từng được
test restore" không đáng tin, đúng nguyên tắc chuẩn vận hành backup.

## RPO/RTO thực tế (đã verify thật trên lab server, 2026-07-09)

- **RPO**: tối đa `archive_timeout=60s` (1 WAL segment có thể chưa kịp
  archive nếu Postgres/VM chết đúng giữa lúc ghi) — tốt hơn nhiều so với
  "0 backup = RPO vô hạn" trước đây. **Verify thật**: ghi 1 audit event
  (id=300) SAU KHI full backup đã hoàn tất, `pg_switch_wal()` để buộc
  archive ngay, chạy `restore-drill.sh` — dữ liệu phục hồi có ĐỦ row 300
  (không chỉ tới row lúc full backup, tức 299) — xác nhận WAL archiving
  liên tục hoạt động đúng, không chỉ full backup mới có tác dụng.
- **RTO**: đo bằng `restore-drill.sh` — **37 giây** thật (từ lúc container
  restore-drill bắt đầu chạy `pgbackrest --delta restore` tới lúc Postgres
  phục hồi sẵn sàng nhận kết nối), trên dataset ~30.8MB/1335 file lúc đo.
  Sẽ tăng theo kích thước dữ liệu thật khi fleet lớn hơn — đo lại định kỳ.

## Việc CHƯA làm (đúng theo roadmap Phase 1/7, không phải thiếu sót)

- **Chưa có standby/replica thật** — đây chỉ là backup/PITR, chưa phải HA
  runtime (mất Postgres vẫn có DOWNTIME trong lúc restore, chỉ không mất
  DỮ LIỆU nữa). Streaming replication + failover là Phase 5.
- **Repo backup vẫn cùng VM với primary** — xem giải thích ở trên, sẽ giải
  quyết khi có VM thứ 2 (Phase 3-4).
- **Chưa mã hoá repo backup** (`repo1-cipher-type`) — backup chứa dữ liệu
  Audit Log/Control Registry, cân nhắc mã hoá trước khi coi đây là bản sao
  "sẵn sàng đưa ra ngoài VM hiện tại" (vd copy sang tape/object storage
  ngoài); chưa làm ở MVP này vì cần thêm quản lý passphrase (secret mới) —
  ghi lại như gap đã biết, không âm thầm bỏ qua.
