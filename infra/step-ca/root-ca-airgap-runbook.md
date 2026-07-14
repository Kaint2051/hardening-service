# Runbook: sinh Root CA trên máy air-gapped (trước khi lên production)

Thực hiện mục 4.1 trong `docs/architecture-proposal.md` ("root CA offline/HSM")
và mục "Root CA hiện đang chạy online trong container (dev)" trong README.md.
Áp dụng cho **triển khai production LẦN ĐẦU** (chưa có ai tin cậy root nào cả).
Nếu đang thay root MỚI cho một hệ thống đã có người tin cậy root CŨ, dùng Zero-
to-CA Migration playbook (README.md) thay vì làm trực tiếp theo runbook này.

## 1. Vì sao cần quy trình riêng

Cấu hình dev hiện tại (`docker-compose.yml` + `DOCKER_STEPCA_INIT_*`) sinh cả
root lẫn intermediate CA trong cùng container `step-ca`, tiện cho phát triển
local nhưng có nghĩa là **root private key nằm trên máy có kết nối mạng** —
một RCE ở bất kỳ service nào chung Docker host (dù đã tách `ca-net` cô lập ở
tầng network) vẫn còn phụ thuộc vào không có lỗ hổng container-escape nào, thay
vì loại bỏ hẳn khả năng đó. Root CA là gốc tin cậy cho toàn bộ mTLS Agent +
SSH cert ngắn hạn — lộ root key nghĩa là phải revoke/tái tạo toàn bộ chuỗi tin
cậy của hệ thống.

Nguyên tắc PKI chuẩn để tránh việc này: root key **không bao giờ** tồn tại
trên bất kỳ máy nào có kết nối mạng, kể cả tạm thời. Chỉ có 2 loại vật liệu
công khai (CSR đi vào, cert đã ký đi ra) băng qua ranh giới air-gap — không có
private key nào băng qua ranh giới đó theo bất kỳ hướng nào.

## 2. Vai trò & yêu cầu vật lý

- **1 máy air-gapped**: laptop/VM không có card mạng hoặc đã tắt hẳn
  networking (không chỉ rút cáp — tắt Wi-Fi/Bluetooth luôn). Không cần bền
  vững — chỉ cần tồn tại đủ lâu để chạy nghi lễ này và các lần renew
  intermediate sau này (xem mục 5). Có thể dùng live-boot USB Linux tối giản,
  cài `step` CLI qua tải trước (không tải trong lúc air-gapped).
- **2 USB rời** (khuyến nghị dùng 2 cái riêng, không dùng chung 1 cái cho cả
  đi lẫn về, để tránh nhầm lẫn version file): 1 cái mang CSR sang, 1 cái mang
  cert đã ký về. Không bắt buộc nhưng giảm rủi ro thao tác nhầm.
- **Khuyến nghị (không bắt buộc)**: 2 người cùng có mặt khi ký root/ký
  intermediate (four-eyes), tương tự tinh thần 3-vai-trò của Content Signing
  Service (`scripts/content-signing/README.md`) — không bắt buộc về mặt kỹ
  thuật vì hệ thống hiện chưa yêu cầu, nhưng nên cân nhắc nếu tổ chức có đủ
  người, vì đây là thao tác không thể hoàn tác dễ dàng nếu làm sai (vd ký
  nhầm root cho tổ chức khác).
- Người thực hiện cần quyền chạy Docker trên cả 2 máy (script tự dùng image
  `smallstep/step-ca` qua Docker nếu máy không có sẵn lệnh `step`).

## 3. Tổng quan luồng

```
   MÁY AIR-GAPPED (không mạng)                    MÁY ONLINE (chạy step-ca thật)
   ───────────────────────────                    ──────────────────────────────
   [1] generate-root-ca.sh
       → root_ca.crt (công khai)
       → root_ca.key (KHÔNG BAO GIỜ rời máy này)
                                                    [2] generate-intermediate-csr.sh
                                                        → intermediate_ca.csr (công khai)
                                                        → intermediate_ca_key (KHÔNG rời máy này)

       (USB #1: intermediate_ca.csr  ─────────────────────────→ mang SANG máy air-gapped)

   [3] sign-intermediate.sh
       (đọc root_ca.{crt,key} + intermediate_ca.csr)
       → intermediate_ca.crt (công khai, đã ký)

       (USB #2: root_ca.crt + intermediate_ca.crt ←───────────── mang VỀ máy online)

                                                    [4] assemble-production-ca.sh
                                                        (đọc root_ca.crt + intermediate_ca.crt
                                                         + intermediate_ca_key đã có sẵn)
                                                        → ghi vào volume step-ca-data
                                                        → khởi động lại step-ca
```

Script tương ứng nằm ở `infra/step-ca/airgap/01-...sh` đến `04-...sh`. Mỗi
script có comment đầu file ghi rõ chạy ở máy nào, thứ tự nào.

**Lưu ý phát hiện qua rehearsal thật (mục 7)**: `secrets/password` trong
volume step-ca là 1 mật khẩu DÙNG CHUNG để tự mở khoá mọi private key lúc
khởi động — không chỉ `intermediate_ca_key`, mà cả `ssh_host_ca_key`/
`ssh_user_ca_key` (SSH host/user CA không thuộc phạm vi nghi lễ air-gap này,
chỉ x509 root/intermediate mới cần offline). Vì vậy script 4 KHÔNG chỉ thay 3
file certs/secrets như mô tả ở mục 3, mà còn đổi MẬT KHẨU (không đổi bản thân
khoá) của 2 file SSH CA đó cho khớp mật khẩu intermediate mới — nếu không,
step-ca sẽ crash lúc khởi động lại với lỗi "decryption password incorrect".

## 4. Các bước thực hiện

Trên máy online, trước tiên đảm bảo `step-ca` đã chạy ít nhất 1 lần để tự sinh
cấu trúc thư mục/provisioner/SSH CA (bản root/intermediate lúc này là hàng TẠM,
sẽ bị thay ở bước 4):

```bash
docker compose up -d step-ca
./infra/step-ca/setup-provisioners.sh   # như đã làm ở môi trường dev
```

Sau đó, theo đúng thứ tự trong sơ đồ mục 3:

```bash
# [1] Trên máy air-gapped, ĐÃ TẮT MẠNG:
./infra/step-ca/airgap/01-generate-root-ca.sh ./out

# [2] Trên máy online, độc lập với bước 1 (thứ tự trước/sau không quan trọng):
./infra/step-ca/airgap/02-generate-intermediate-csr.sh ./out

# --- copy ./out/intermediate_ca.csr từ máy online sang máy air-gapped (USB #1) ---

# [3] Trên máy air-gapped:
./infra/step-ca/airgap/03-sign-intermediate.sh ./out

# --- copy ./out/root_ca.crt + ./out/intermediate_ca.crt từ máy air-gapped
#     về máy online (USB #2), đặt vào cùng thư mục ./out đã dùng ở bước 2
#     (nghĩa là ./out lúc này có đủ: intermediate_ca_key (từ bước 2) +
#     root_ca.crt + intermediate_ca.crt (mang về từ bước 3)) ---

# [4] Trên máy online:
STEPCA_VOLUME=<tên-volume-thật> ./infra/step-ca/airgap/04-assemble-production-ca.sh ./out
```

`STEPCA_VOLUME` mặc định là `hardening-console_step-ca-data` (tên volume theo
quy ước Docker Compose `<tên-project>_<tên-volume>`) — kiểm tra tên thật bằng
`docker volume ls | grep step-ca-data` nếu project không tên `hardening-console`.

Mỗi script đều tự kiểm tra file đầu vào cần thiết đã có chưa và dừng với thông
báo rõ ràng nếu thiếu — không cần nhớ thứ tự chính xác tuyệt đối, cứ chạy theo
thứ tự trên và làm theo hướng dẫn khi script báo lỗi.

## 5. Sau khi triển khai: lưu trữ & renew

- **root_ca.key**: sao lưu tối thiểu 2 bản trên 2 thiết bị lưu trữ vật lý
  riêng biệt (vd 2 USB mã hoá), cất ở 2 nơi an toàn khác nhau (vd 1 tủ tại
  chỗ + 1 tủ khác toà nhà/chi nhánh). Không bao giờ cắm USB chứa bản sao lưu
  này vào máy có mạng. Ghi lại fingerprint (`step certificate fingerprint
  root_ca.crt`) vào biên bản giấy hoặc nơi lưu trữ tách biệt khỏi cả 2 USB, để
  đối chiếu khi cần dùng lại (renew intermediate — xem dưới).
- **Máy air-gapped**: nếu không giữ máy vật lý thường trực, ít nhất phải giữ
  được khả năng tái tạo môi trường air-gapped tương đương (live-boot USB có
  cài sẵn `step` CLI, không cần chính máy đó) — cần cho lần renew intermediate
  tiếp theo.
- **Renew intermediate CA** (mặc định 5 năm, xem `INTERMEDIATE_CA_VALIDITY`
  trong script 03 — làm lại TRƯỚC khi hết hạn, không cần đợi hết hạn hẳn mới
  làm): lặp lại bước 2 → 3 → 4 ở trên. **Không cần làm lại bước 1** — root giữ
  nguyên (mặc định 10 năm, xem `ROOT_CA_VALIDITY` trong script 01).
- **KHÔNG** có endpoint hay job tự động nào theo dõi ngày hết hạn intermediate
  hộ — đây là quy trình vận hành thủ công, cần tự đặt nhắc lịch (vd trước hạn
  ít nhất 3 tháng) ngoài hệ thống.

## 6. Disaster recovery

Nếu **cả** máy air-gapped **và** mọi bản sao lưu `root_ca.key` đều mất (cháy,
hỏng ổ đĩa toàn bộ các bản sao, thất lạc...): không có cách khôi phục — phải
làm lại từ bước 1 với root CA MỚI, sau đó redistribute `root_ca.crt` mới tới
mọi nơi đang tin cậy root cũ (trust store Agent, `known_hosts` SSH CA, cấu
hình `CONTENT_SIGNING_TRUSTED_FINGERPRINT` không liên quan vì đó là GPG khác
hệ thống này) theo đúng luồng Zero-to-CA Migration playbook — coi như migrate
sang 1 CA hoàn toàn mới. Đây là lý do mục "sao lưu 2 bản, 2 nơi" ở mục 5 không
phải tuỳ chọn mà là yêu cầu tối thiểu.

Nếu chỉ mất intermediate_ca_key ở máy online (vd ổ đĩa hỏng) nhưng root vẫn
còn nguyên trên máy air-gapped: không phải disaster — chạy lại bước 2 → 3 → 4
để cấp intermediate MỚI (không cần đổi root, không cần redistribute lại
root_ca.crt vì root không đổi).

## 7. Đã rehearsal ở đâu

Toàn bộ quy trình + cả 4 script đã được diễn tập đầy đủ (không phải chỉ đọc
code) trên lab server bằng cách mô phỏng máy air-gapped bằng 1 container Docker
chạy `--network none` (đảm bảo cấu trúc "không có khả năng nối mạng" ở tầng hệ
điều hành, không chỉ theo thủ tục) và máy online bằng service `step-ca` thật
trong 1 project Docker Compose riêng, tách biệt hoàn toàn khỏi volume
`step-ca-data` đang chạy thật của lab — không đụng tới CA đang phục vụ. Kết
quả: cả 4 script chạy đúng theo thứ tự, cert intermediate mới xác nhận verify
chain thành công về root mới, step-ca khởi động lại khoẻ mạnh, và đã xác nhận
`secrets/root_ca_key` không tồn tại trong volume online sau khi hoàn tất — xem
kết quả trong README.md.
