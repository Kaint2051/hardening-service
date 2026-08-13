# Hướng dẫn soạn nội dung TCVN / Thông tư (dành cho người phụ trách compliance)

Tài liệu này dành cho người **không nhất thiết biết code**, chỉ cần biết viết
Ansible cơ bản, được giao soạn nội dung hardening theo TCVN/Thông tư của Việt
Nam (mục "Việc CHƯA làm" trong README — hạng mục duy nhất cần chuyên môn
compliance, không phải kỹ thuật thuần).

## 1. Vì sao lại theo đúng khuôn dạng ComplianceAsCode

Hệ thống đã có sẵn nội dung CIS (Ubuntu/Debian) và STIG (DISA) theo đúng định
dạng do dự án mã nguồn mở [ComplianceAsCode](https://github.com/ComplianceAsCode/content)
tự sinh ra. Tab **"Template"** trong Control Registry (Web UI) đọc trực tiếp
định dạng này để rule-editor duyệt/chọn rule và tự tạo Control — xem
`control-templates/README.md`. Nếu nội dung TCVN/Thông tư được viết **đúng
cùng khuôn dạng**, nó sẽ chạy được qua chính công cụ đó ngay lập tức, không
cần ai sửa code. Đây là lý do tài liệu này tồn tại: hướng dẫn viết đúng khuôn
dạng, không phải hướng dẫn lập trình.

## 2. Hai giai đoạn tách biệt — đừng nhầm lẫn

| | Giai đoạn A — Soạn Control nháp | Giai đoạn B — Bật tự động sửa thật |
|---|---|---|
| Việc làm | Viết playbook đúng khuôn dạng, nộp qua tab Template | Đóng gói + ký qua quy trình 3 vai trò |
| Kết quả | 1 `Control` `maturity=draft` | 1 `RemediationVariant` đã ký, dùng được cho Active Response/canary |
| Cần ký GPG? | **Không** | **Bắt buộc** (Puller/Reviewer/Signer, 3 người, 3 key khác nhau) |
| Ai làm | Bạn (người soạn compliance) | Đúng quy trình `scripts/content-signing/` đã có sẵn |

Tài liệu này tập trung vào **Giai đoạn A**. Giai đoạn B dùng lại nguyên quy
trình đã có ở mục 5 — bạn không cần hiểu chi tiết phần đó để bắt đầu viết nội
dung.

## 3. Khuôn dạng bắt buộc của file playbook

Đây là cấu trúc y hệt file ComplianceAsCode tự sinh — copy khung này rồi điền
task thật vào, đừng đổi cấu trúc:

```yaml
- name: Ansible Playbook cho TCVN 11930:2017 - Nhóm cấu hình Linux
  hosts: all
  vars:
    banner_text: "Hệ thống chỉ dành cho người dùng được uỷ quyền."
  tasks:
    - name: Thu thập thông tin package (luôn chạy trước)
      package_facts:
        manager: auto
      tags:
        - always

    - name: Đảm bảo đăng nhập root qua SSH bị vô hiệu hoá
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PermitRootLogin'
        line: 'PermitRootLogin no'
      tags:
        - tcvn_disable_root_login
        - TCVN-11930-8.2.1
        - medium_severity
        - low_complexity
        - low_disruption

    - name: Đảm bảo banner đăng nhập được cấu hình đúng nội dung
      copy:
        dest: /etc/issue.net
        content: "{{ banner_text }}"
      tags:
        - tcvn_configure_banner
        - TCVN-11930-8.3.4
        - low_severity
        - low_complexity
        - low_disruption
```

Các quy tắc **bắt buộc** (parser dựa đúng vào cấu trúc này, sai sẽ báo lỗi rõ
ràng chứ không âm thầm parse sai):

1. **Đúng 1 play**, có `vars:` và `tasks:` — dòng `  tasks:` phải tồn tại y
   hệt (2 khoảng trắng thụt đầu, không thừa/thiếu).
2. Mỗi task bắt đầu bằng `  - name: ...` (2 khoảng trắng) — không thụt lề
   khác đi.
3. **1 "rule"** (1 hạng mục hardening trong TCVN/Thông tư) = 1 hoặc nhiều
   task **liền kề nhau**, cùng chia sẻ **đúng 1 tag định danh rule** dạng
   `snake_case` (ví dụ `tcvn_disable_root_login`) — đây là tag đầu tiên
   không thuộc danh sách "tag đặc biệt" bên dưới, dùng làm rule ID hiển thị
   trên UI. Đặt tag này **đầu tiên** trong danh sách `tags:` của task.
4. Task tiền điều kiện (chạy luôn, không phải 1 rule cụ thể — ví dụ thu thập
   fact) thì gắn **đúng 1 tag duy nhất**: `tags: [always]`. Task này sẽ tự
   động có mặt trong MỌI Control tạo ra từ template, không cần rule-editor
   chọn.
5. Các tag **không** dùng làm rule ID (được tự nhận diện, không cần khai báo
   gì thêm):
   - Mức độ nghiêm trọng: `low_severity` / `medium_severity` / `high_severity`
   - Độ phức tạp: `low_complexity` / `medium_complexity` / `high_complexity`
   - Mức gây gián đoạn: `low_disruption` / `medium_disruption` / `high_disruption`
   - Tham chiếu chuẩn (xem mục 4): bất kỳ tag nào bắt đầu bằng
     `NIST-`, `CJIS-`, `PCI-DSS`, `DISA-STIG-`, `srg_`, `anssi_`, `hipaa_`,
     `stigid_`, `cis-`, `cis_`, **và** — quan trọng cho TCVN — bạn nên tự đặt
     tiền tố riêng nhất quán (ví dụ `TCVN-11930-...`, `TT12-2022-...`) để tag
     đó được nhận diện là "tham chiếu chuẩn" chứ không bị hiểu nhầm là rule ID
     thứ 2 của cùng 1 rule.
6. Biến Jinja (`{{ tên_biến }}`) dùng trong task của 1 rule, nếu có khai báo
   trong `vars:` ở đầu file, sẽ tự động thành "biến có thể override theo host"
   khi Control được tạo (operator sau này chỉnh riêng cho từng máy qua trang
   Hosts) — không cần làm gì thêm ngoài khai báo trong `vars:`.

## 4. Tag tham chiếu chuẩn → tự động điền `StandardMapping`

Khi rule-editor bấm "Tạo Control" từ template, mỗi tag tham chiếu chuẩn (mục
3.5) trên rule được chọn sẽ **tự động tách** thành `standard` +
`section_id` theo quy tắc: cắt phần cuối cùng giống mã số/chương/điều (chữ,
số, dấu chấm, ngoặc) ra khỏi phần đầu.

Ví dụ tag `TCVN-11930-8.2.1` → `standard="TCVN-11930"`,
`section_id="8.2.1"`. Tag `TT12-2022-Dieu15` → `standard="TT12-2022"`,
`section_id="Dieu15"`.

Đặt tên tag **nhất quán** trong toàn bộ file (cùng 1 văn bản pháp quy nên
dùng cùng 1 tiền tố) để tránh tạo ra nhiều `standard` khác nhau cho cùng 1
văn bản. Rule-editor vẫn xem lại được trước khi tạo Control thật (không bị
tạo mù) — nếu tách sai, có thể sửa tay sau khi Control đã tạo qua API
`POST /controls/{id}/standard-mappings` bình thường.

## 5. Nộp file

1. Đặt tên file theo quy ước `<id>.yml`, ví dụ `tcvn11930-linux.yml` hoặc
   `tt12-2022-btttt-linux.yml` (chỉ chữ/số/gạch ngang/gạch dưới — dùng làm
   URL path segment).
2. Đưa file vào thư mục `control-templates/` trong working tree, review nội
   dung cùng người phụ trách kỹ thuật trước khi đẩy lên server (đây chỉ là
   **input soạn thảo**, chưa phải nội dung "đã duyệt production" — Control
   tạo ra vẫn ở trạng thái `draft`, vẫn phải qua four-eyes chuẩn của hệ
   thống trước khi lên `production`).
3. Sau khi có trên server: `docker compose restart orchestrator` (không cần
   build lại image — xem `control-templates/README.md`).
4. Vào tab "Template" trên Web UI, chọn file vừa thêm, duyệt danh sách rule,
   chọn rule cần dùng, xem trước playbook ghép ra, rồi tạo Control.

## 6. Khi nào cần quy trình ký 3 vai trò (Giai đoạn B)

Control tạo từ bước trên **chưa tự sửa được gì trên máy thật** — nó chỉ là
metadata + playbook nháp. Để bật tính năng tự động sửa (dry-run/apply thật,
canary, Active Response), nội dung playbook thật (có thể khác bản nháp ban
đầu, do Reviewer/Signer là người khác, có thể chỉnh sửa/bổ sung role) phải đi
qua đúng quy trình đã có sẵn — xem `scripts/content-signing/README.md`:

```bash
./pull.sh <url-hoặc-file://đường-dẫn-nội-bộ> tcvn11930-linux-v1   # Puller
./review.sh staging/tcvn11930-linux-v1-<timestamp>                # Reviewer
./sign.sh reviewed/tcvn11930-linux-v1-<timestamp>                 # Signer
```

3 vai trò **bắt buộc phải là 3 người khác nhau, 3 máy/keyring GPG khác
nhau** — script tự chặn nếu phát hiện trùng key. Sau khi ký xong, tạo
`RemediationVariant` trỏ `remediation_ref` tới đúng thư mục trong
`scripts/content-signing/signed/` qua `POST /controls/{id}/remediation-variants`.

## 7. Giới hạn — việc KHÔNG nên tự làm thay

Nội dung TCVN/Thông tư mang tính pháp lý — **không nên để trợ lý AI tự suy
diễn ánh xạ điều khoản sang cấu hình kỹ thuật cụ thể thay cho người có
chuyên môn compliance**. Tài liệu này chỉ hướng dẫn **khuôn dạng kỹ thuật**
để nội dung do con người soạn có thể chạy được trong hệ thống, không thay
thế việc đọc hiểu văn bản pháp quy và quyết định ánh xạ đúng.
