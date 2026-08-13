# Control Templates

Nguồn nội dung CHÍNH THỨC (ComplianceAsCode/CIS Benchmark — CÙNG dự án cung
cấp nội dung cho tính năng "Quét" qua OpenSCAP) dùng cho tab "Template"
trong Control Registry (Web UI) — xem `apps/orchestrator/app/control_templates.py`.

Mỗi file `<id>.yml` ở đây = 1 playbook Ansible do ComplianceAsCode tự sinh
cho 1 product+profile cụ thể. `<id>` (không có đuôi `.yml`) là ID hiển thị
trên UI.

## Đã có

- `ubuntu2204-cis_level1_server.yml` — CIS Ubuntu Linux 22.04 LTS Benchmark
  v2.0.0, Level 1 Server. Nguồn:
  https://github.com/ComplianceAsCode/content/releases/tag/v0.1.81
  (`ansible/ubuntu2204-playbook-cis_level1_server.yml`, đã verify sha512
  khớp công bố chính thức trước khi lấy).
- `ubuntu2204-stig.yml` — Canonical Ubuntu 22.04 LTS Security Technical
  Implementation Guide (STIG) V2R7 (DISA), 639 task/nhiều rule. Cùng release
  v0.1.81 với file CIS ở trên (`ansible/ubuntu2204-playbook-stig.yml`), đã
  verify sha512 tarball trước khi lấy. **Chỉ dùng cho tab "Template" (tạo
  Control draft) — chưa có datastream STIG tương ứng cho tính năng "Quét"**
  (gói `ssg-debderived`/`ssg-debian` 0.1.65-1 đang cài trong
  `apps/execution-env/Dockerfile` chỉ có profile CIS/standard cho Ubuntu
  22.04, không có `stig`; cần quyết định riêng có nâng datastream lên bản
  mới hơn hay không trước khi thêm profile scan STIG).

## Thêm template mới

1. Tải bản phát hành ComplianceAsCode mới nhất phù hợp (hoặc bản khác:
   RHEL, Debian, STIG profile...) từ
   https://github.com/ComplianceAsCode/content/releases — **verify sha512
   khớp file `.sha512` cùng release trước khi dùng**.
2. Giải nén, lấy đúng file cần trong thư mục `ansible/` (tên dạng
   `<product>-playbook-<profile>.yml`).
3. Copy vào đây, đổi tên theo quy ước `<product>-<profile>.yml` (không dấu
   gạch dưới lẫn gạch ngang tuỳ tiện — dùng làm URL path segment, chỉ nên
   gồm chữ/số/gạch ngang/gạch dưới).
4. Rebuild + restart orchestrator (`docker compose up -d orchestrator` —
   không cần rebuild image, chỉ cần remount volume nếu thêm file mới khi
   container đang chạy thì restart để đảm bảo, dù thực tế bind-mount
   directory tự cập nhật ngay).

## Định dạng bắt buộc (parser dựa vào cấu trúc CỐ ĐỊNH này)

- 1 play duy nhất, có `vars:` (dùng chung) và `tasks:` (danh sách phẳng).
- Mỗi dòng bắt đầu task phải đúng dạng `  - name: ...` (2 khoảng trắng thụt
  đầu dòng) — đúng như ComplianceAsCode tự sinh, KHÔNG chỉnh sửa thụt lề tay.
- Rule XCCDF = nhiều task liền kề dùng CHUNG đúng 1 tag dạng snake_case
  không trùng tiền tố chuẩn khác (`NIST-`, `CJIS-`, `PCI-DSS`, `DISA-STIG-`...)
  — xem `_is_rule_id_tag` trong `control_templates.py`.
- Task tag `["always"]` (vd "Gather the package facts") được TỰ ĐỘNG gộp vào
  mọi playbook sinh ra từ template này, không cần chọn.

File KHÔNG đúng định dạng trên (thiếu dòng `  tasks:`, hoặc tự viết tay
không theo cấu trúc ComplianceAsCode) sẽ bị `list_control_templates`/
`list_template_rules` báo lỗi rõ ràng, không parse sai âm thầm.
