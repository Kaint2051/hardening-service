# Đề xuất kiến trúc: Web-Console quản lý Hardening & Cấu hình Linux

## Bối cảnh

Dự án đang ở giai đoạn ý tưởng (thư mục trống, chưa có code). Mục tiêu: xây một web-console cho phép quản lý hardening và cấu hình service trên nhiều máy chủ Linux, hướng tới người dùng ít kinh nghiệm bảo mật/CLI. Do thư mục dự án nằm trong tenant "My VNNIC", nhiều khả năng đây là hệ thống nội bộ cho hạ tầng Internet/viễn thông trọng yếu của Việt Nam — điều này nâng yêu cầu bảo mật, tuân thủ quy định trong nước, và khả năng vận hành với Internet hạn chế lên mức bắt buộc, không phải tùy chọn.

Các quyết định đã chốt cùng người dùng:
- **Mô hình quản lý:** Hybrid — agentless (SSH) cho scan/audit/one-shot; agent-based cho máy cần giám sát liên tục/tự remediate.
- **Quy mô:** ban đầu **tối đa 50 máy** (nhiều distro: RHEL/CentOS/Rocky, Ubuntu, Debian) — đây là quy mô mục tiêu hiện tại, không phải "pilot" cho một hệ 500+ máy; có thể mở rộng sau này nếu tổ chức quyết định, nên kiến trúc tránh khoá cứng các quyết định gây khó mở rộng (Orchestrator stateless, Control Registry không giả định 1 site cố định), nhưng KHÔNG đầu tư trước cho HA/multi-site/Kubernetes ở giai đoạn hiện tại.
- **Môi trường:** on-premise, Internet hạn chế (qua proxy, không phụ thuộc cloud).
- **Chuẩn compliance đồng thời:** CIS Benchmarks, DISA STIG, quy định VN (TCVN/Thông tư BTTTT/Luật ATTTM/ANM), và policy tự định nghĩa.
- **Tech stack:** chưa chốt — đề xuất bên dưới.

Bản đề xuất dưới đây là kết quả của một quy trình phân tích đa góc nhìn (MVP/pragmatic, enterprise-robustness, platform security, compliance-mapping, build-vs-buy) đã qua 2 vòng phản biện bảo mật độc lập để tìm và vá các lỗ hổng thiết kế trước khi trình bày.

---

## 1. Nguyên tắc thiết kế cốt lõi (bất biến, áp dụng mọi giai đoạn)

Console này nắm quyền root/sudo trên các máy chủ hạ tầng trọng yếu (ban đầu tối đa 50, có thể mở rộng sau) ⇒ bản thân nó là mục tiêu tấn công giá trị cao nhất (crown-jewel), không phải một CRUD app. Các nguyên tắc sau **không được hoãn để đổi lấy tốc độ MVP**:

1. **Không standing privilege** — không static SSH key, không sudo session thường trực; mọi truy cập là Just-In-Time, cấp SSH certificate ngắn hạn (TTL 5–15 phút).
2. **Dry-run/diff bắt buộc** trước mọi remediation thật — không có đường tắt "apply trực tiếp".
3. **Four-eyes (maker-checker)** cho mọi thay đổi trên production/Tier cao — người đề xuất ≠ người duyệt.
4. **Audit log append-only, hash-chain**, forward song song ra log server nằm ngoài quyền quản trị của chính console.
5. **Canary/batch rollout bắt buộc** — không bao giờ áp dụng thay đổi cho toàn bộ fleet trong một lệnh.
6. **Ký số nội dung policy/benchmark** trước khi hệ thống chấp nhận nạp — chống chèn rule độc hại qua kênh cập nhật.
7. **Rollback/backup được tạo trước khi remediate**, không phải "cố sinh ra sau khi lỗi".
8. **Không tự chế crypto/IAM** — dùng OSS đã kiểm chứng (SSH CA, Keycloak) thay vì tự viết. **Ngoại lệ có chủ đích:** Agent host được quyết định tự phát triển (xem mục 4.3) để đội ngũ sở hữu hoàn toàn thành phần có quyền thực thi trên fleet — đổi lại, agent phải qua kiểm thử/pentest riêng trước khi bật tính năng tự động remediate (xem rủi ro #3 mục 8).
9. **Assume breach** — mọi quyết định kiến trúc phải trả lời được: "nếu console bị chiếm, kẻ tấn công làm được gì tối đa, trong bao lâu, và có bị phát hiện ngay không?"

---

## 2. Kiến trúc tổng thể

```
┌───────────────────── MANAGEMENT ZONE (VLAN cô lập, không route thẳng Internet) ─────────────────────┐
│                                                                                                        │
│  Web Console (SPA+API) ──▶ Keycloak (SSO/OIDC/LDAP/MFA)     CA/Secrets Cluster (OpenBao/step-ca)      │
│         │                                                    -- HOST/NETWORK RIÊNG, tách khỏi web --  │
│  Orchestrator API (job scheduler, approval workflow,                       │                          │
│  RBAC/OPA, canary gate theo control-class) ◀────────────────────────────────┘ (chỉ Orchestrator        │
│         │  tạo job + xin cert ngắn hạn (KHÔNG giao quyền cấp cert cho executor)   được gọi CA)         │
│         ▼                                                                                              │
│  Ephemeral Execution Env      Agent Manager tự phát        Audit Log (append-only,   Content Signing   │
│  (container/VM huỷ sau        triển (network segment        hash-chain, forward       Service (ký       │
│  mỗi job; Ansible role bên    riêng; Active Response        sang log server độc lập)  offline bundle,   │
│  thứ ba pin version+hash-     giới hạn playbook đã                                     quy trình 2-      │
│  verify)                      pre-approved)                                            người)           │
└─────────┼───────────────────────────┼──────────────────────────────────────────────────────────────────┘
          │ SSH (cert TTL ngắn)       │ mTLS, agent outbound (reverse-connection qua broker theo site)
          ▼                           ▼
┌────────────────────── PRODUCTION ZONE (nhiều site/DC, WAN có thể gián đoạn) ─────────────────────────┐
│  [Site] Local Relay/Jump-node (buffer job + log khi mất WAN) — [Tier 0: DNS/core] [Tier 1] [Tier 2]    │
│  Mỗi máy: sshd (TrustedUserCAKeys) + (tier 0/1) Agent tự phát triển + out-of-band mgmt (IPMI/iLO/serial)│
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Luồng chính:** UI → Orchestrator kiểm tra RBAC/OPA → thay đổi ghi cần approve (four-eyes) → Orchestrator xin cert ngắn hạn + khởi tạo Ephemeral Execution Env mới → job chạy (Ansible agentless hoặc Active Response của Agent Manager đã pre-approved) → cert/container huỷ ngay sau job → kết quả + audit event ghi hash-chain → Control Registry cập nhật compliance score.

**Điểm thiết kế quan trọng dễ bị bỏ sót:**
- **Tách "người xin cert" khỏi "nơi cert được dùng"**: chỉ Orchestrator được gọi CA; Execution Env nhận cert đã cấp sẵn, tự nó không thể xin cert mới — nếu 1 job bị compromise, attacker không thể tự gia hạn quyền truy cập.
- **Agent Manager là control-plane thứ hai**, không chỉ là "server giám sát" — Active Response có khả năng thực thi trên toàn fleet, nên phải nằm trong network zone riêng và có audit/break-glass ngang hàng với CA, nếu không sẽ trở thành đường vòng qua mặt toàn bộ approval workflow. Vì agent này tự phát triển (không phải Wazuh), toàn bộ vòng đời bảo mật của nó do đội ngũ tự chịu trách nhiệm — xem thiết kế chi tiết ở mục 4.3.
- **Ephemeral Execution Environment** (container/VM tạo–huỷ theo từng job) thay vì một "control node" sống lâu dài — một control node cố định nắm cert + playbook = RCE một lần là RCE cả fleet.

**Đơn giản hóa cho quy mô ban đầu (≤50 máy):** với quy mô này thường chỉ 1 site, nên **Local Relay/Jump-node có thể bỏ qua ở giai đoạn đầu** — agent kết nối thẳng tới Agent Manager, Execution Env SSH thẳng tới host qua 1 bastion duy nhất. Thiết kế vẫn để chỗ thêm Local Relay sau này nếu mở rộng đa site (không cần đổi giao thức agent hay schema dữ liệu, chỉ thêm một lớp buffer/relay).

---

## 3. Policy & Compliance Mapping Engine (Control Registry)

Đây là thành phần "chất keo" cốt lõi, thiết kế đúng ngay từ đầu vì sửa sau rất tốn kém:

```
Control (id, mô_tả_tự_nhiên, severity, category)
   ├── StandardMapping (N-N): control_id, standard [CIS|STIG|TCVN|BoTTTT|custom], standard_ref_id, version
   └── RemediationVariant (N-N theo distro): control_id, distro, init_system,
                                              check_script_ref, remediation_ref, rollback_ref,
                                              maturity [verified|community|untested]
```

- Nguồn rule kỹ thuật: **ComplianceAsCode/OpenSCAP** (không tự viết scanner). Coverage của distro như Debian yếu hơn RHEL — gắn nhãn `maturity`; control ở mức `community/untested` mặc định **khoá auto-remediate**, chỉ cho dry-run cho tới khi kiểm định qua lab.
- UI hiển thị ma trận **control × chuẩn × distro**; hệ thống **từ chối** job nếu không tìm thấy `RemediationVariant` khớp đúng distro/version của máy đích — tránh áp nhầm lệnh RHEL lên Debian.
- **Một nguồn sự thật** cho điểm compliance chính thức = OpenSCAP; SCA của Agent tự phát triển dùng cho cảnh báo liên tục, đối chiếu định kỳ với OpenSCAP, lệch điểm → cảnh báo admin thay vì tự động ghi đè.
- **Chuỗi cung ứng nội dung (3 vai trò tách biệt bắt buộc)**: Puller (tải nội dung gốc về khu cách ly) → Reviewer (kiểm diff, độc lập với Puller) → Signer (ký sau khi Reviewer duyệt, key ở service riêng). Không một người vừa tải vừa ký — nếu không, bước "ký số chống chèn rule độc hại" chỉ là hình thức.
- Mapping TCVN/Thông tư BTTTT: **không có OSS sẵn**, cần đội pháp lý/ATTT trong nước biên soạn thủ công, nạp qua đúng quy trình 3 vai trò trên, có job tự động phát hiện khi CIS/STIG đổi ID làm mapping cũ bị gãy.

---

## 4. Bảo mật nền tảng — hạng mục KHÔNG được hoãn

| # | Hạng mục | Vì sao |
|---|---|---|
| 4.1 | SSH cert ngắn hạn (OpenBao/step-ca), root CA offline/HSM, **host/network CA tách khỏi web console** | RCE/SQLi ở tầng web không tự động leo thang thành quyền ký CA |
| 4.2 | Execution Environment ephemeral, Ansible role bên thứ ba pin version + hash-verify | Chặn "control node sống lâu = RCE toàn fleet" |
| 4.3 | Agent Manager (tự phát triển) coi là crown-jewel thứ hai: network riêng, four-eyes cho thay đổi Active Response ruleset, audit/break-glass riêng | Chặn đường vòng qua mặt approval workflow |
| 4.4 | **Zero-to-CA Migration playbook** riêng cho onboarding tối đa 50 máy hiện hữu lần đầu (dùng credential cũ theo batch nhỏ, canary, thu hồi ngay sau khi migrate từng máy) | Đây là cửa sổ rủi ro lớn nhất vòng đời hệ thống — vòng lặp gà-trứng chưa được thiết kế thường bị bỏ sót |
| 4.5 | Phân loại control theo rủi ro tự-khoá-kênh: **Nhóm A** (an toàn canary trực tiếp) vs **Nhóm B** (đổi cipher/PAM/port/firewall — bắt buộc test lab trước, cấm canary production trực tiếp) | Canary kiểu phần mềm không phát hiện được rule tự khoá SSH ngay lập tức |
| 4.6 | **Out-of-band recovery** (IPMI/iLO/serial/hypervisor snapshot) bắt buộc cho Tier 0/1 trước khi áp control Nhóm B | Rollback qua SSH có thể tự vô hiệu hoá đúng kênh dùng để rollback |
| 4.7 | RBAC 6 vai trò tối thiểu (Viewer/Auditor/Rule-Editor/Approver/Operator/Admin), Admin không tự duyệt thay đổi của chính mình; dùng OPA/Rego thay vì if-else rải rác | Giảm lỗi logic khi quyền scope theo role × asset-group × tier |
| 4.8 | Network segmentation **theo site** (không cố định 2 zone): mỗi site có Local Relay/Jump-node buffer job/log khi WAN gián đoạn — **hoãn tới khi mở rộng đa site**, ở quy mô ≤50 máy dùng 1 zone/1 bastion là đủ | Hạ tầng viễn thông thường phân vùng địa lý, "Internet hạn chế" là ràng buộc thật, không phải khẩu hiệu; nhưng tránh xây multi-site khi chưa cần |
| 4.9 | Tách 2 nhóm nhân sự: vận hành CA/Vault/Agent Manager (chuyên trách, chấp nhận CLI phức tạp) vs người dùng cuối UI (ẩn hoàn toàn độ phức tạp, chỉ thấy nút "Xin quyền truy cập 30 phút") | Mục tiêu UX "dễ dùng cho người mới" chỉ đúng cho phần ngọn nếu không tách rõ 2 persona |

### 4.3 chi tiết — Agent tự phát triển (thay thế Wazuh)

Quyết định: đội ngũ muốn sở hữu 100% source code của thành phần có quyền thực thi trên fleet, không phụ thuộc OSS bên thứ ba cho phần này. Thiết kế dưới đây giữ nguyên toàn bộ nguyên tắc bảo mật đã áp cho Wazuh trước đó, chỉ thay đổi ai chịu trách nhiệm vòng đời bảo mật.

**Ngôn ngữ: Go** — biên dịch tĩnh thành 1 binary duy nhất, không cần runtime, dễ deploy đồng loạt lên nhiều distro/kiến trúc, xử lý concurrency tốt cho hàng trăm kết nối agent đồng thời.

**Tách 2 tiến trình trên mỗi máy** (giảm blast radius nếu agent bị tấn công qua mạng):
- **Reporter** — quyền tối thiểu, giữ kết nối mTLS outbound tới Agent Manager, gửi heartbeat/kết quả scan/log FIM. Đây là phần duy nhất lộ ra mạng.
- **Executor** — quyền root khi cần remediate, nhưng chỉ nhận lệnh qua Unix socket nội bộ từ Reporter (không expose mạng), verify chữ ký job trước khi chạy.

**Tái dùng PKI đã có** (không dựng CA riêng cho agent):
- Enrollment: Orchestrator phát bootstrap token dùng-một-lần (TTL vài phút) khi thêm host mới → agent dùng token xin client cert mTLS từ step-ca đã có sẵn trong kiến trúc → token vô hiệu ngay sau khi dùng.
- Cert TTL ngắn, agent tự renew trước khi hết hạn; xác thực 2 chiều (agent pin CA nội bộ, server chỉ tin cert hợp lệ còn hạn).

**Chống các lỗi kinh điển của agent tự viết:**
- Update binary phải ký (cosign/GPG) + verify trước khi agent tự áp dụng; server chỉ định version tối thiểu cho phép chạy → chống rollback về bản có lỗ hổng.
- Active Response **không nhận shell command tự do** — chỉ nhận `control_id` + `remediation_ref` đã có trong Control Registry; Executor verify hash script khớp bản đã ký qua Content Signing Service trước khi chạy, từ chối nếu không khớp.
- FIM: MVP dùng so sánh hash định kỳ (đơn giản); nâng lên `inotify` real-time ở giai đoạn sau nếu cần.

**Đánh đổi cần lưu ý:** đây là hạng mục kỹ thuật khó nhất dự án — tương đương xây một mini-EDR, cần kỹ sư có kinh nghiệm crypto/network security (không chỉ web developer), tốn nhiều thời gian hơn đáng kể so với tích hợp Wazuh, và không có cộng đồng OSS vá lỗi hộ — team tự chịu trách nhiệm phát hiện/vá lỗ hổng trong chính agent. **Khuyến nghị lộ trình:** pilot phần SCA/báo cáo trước, chưa bật Active Response tự động remediate cho tới khi agent đã qua kiểm thử/pentest riêng — bật remediate tự động là mốc rủi ro cao nhất, nên tách thành milestone độc lập.

**Về việc giới hạn quy mô xuống tối đa 50 máy:** điều này KHÔNG làm giảm độ khó kỹ thuật của agent (vẫn cùng một bài toán crypto/protocol dù chạy trên 1 hay 500 máy — không có "phiên bản rút gọn" an toàn hơn), nhưng làm giảm đáng kể **blast radius vận hành**: 50 điểm bề mặt tấn công thay vì 500+, và một lỗi (nếu xảy ra) ảnh hưởng tới ít máy hơn. Đây là lý do hợp lý để chấp nhận đánh đổi rủi ro kỹ thuật đổi lấy quyền sở hữu source code — nhưng kỷ luật kỹ thuật (pentest trước khi bật Active Response, không nhận shell tự do, ký/verify update) vẫn phải giữ nguyên, không được nới lỏng vì "chỉ có 50 máy".

---

## 5. Công cụ mã nguồn mở nên tái dụng (không tự viết)

| Nhu cầu | Công cụ | Lý do không tự viết |
|---|---|---|
| Rule CIS/STIG + remediation | **ComplianceAsCode / OpenSCAP** | Đã kiểm định rộng rãi |
| Thực thi agentless | **Ansible + ansible-runner** | Idempotency, check-mode/--diff có sẵn |
| Base hardening role | **dev-sec / ansible-lockdown** (pin version, hash-verify) | Điểm khởi đầu tốt |
| SSH CA | **OpenBao** (ưu tiên hơn Vault do license BSL) **+ step-ca** | Tránh rủi ro pháp lý license cho hệ thống nhà nước |
| SSO/MFA | **Keycloak** | OIDC/SAML/LDAP self-host |
| Policy/RBAC | **OPA (Open Policy Agent)** | Tránh lỗi logic phân quyền rải rác |
| Ký nội dung | **cosign/GPG** | Chuẩn công nghiệp cho supply-chain signing |
| Observability | **Prometheus + Grafana** | Không dùng làm dashboard compliance chính |

**Bắt buộc tự viết** (không có OSS tương đương, hoặc do quyết định sở hữu 100% source code): Control Registry mapping đa chuẩn, Orchestrator/approval workflow, UI đơn giản hóa, Ephemeral Execution Env orchestration, cơ chế đối chiếu OpenSCAP vs SCA của agent, **Agent host (Reporter+Executor) + Agent Manager** (xem thiết kế chi tiết mục 4.3).

---

## 6. Tech stack đề xuất

| Lớp | Lựa chọn | Lý do |
|---|---|---|
| Backend/Orchestrator | Python + FastAPI | Hệ sinh thái SSH/Ansible/OpenSCAP chủ yếu Python; tách job-runner sang Go sau nếu nghẽn concurrency |
| Agent host + Agent Manager (tự phát triển) | Go | Biên dịch tĩnh 1 binary, không runtime, dễ deploy đa distro, concurrency tốt cho hàng trăm kết nối agent |
| Frontend | React + TypeScript + MUI/Ant Design | Component sẵn cho dashboard/diff-view |
| Execution Env | Docker container (cân nhắc Firecracker microVM nếu cần cách ly mạnh hơn) | Ephemeral theo từng job |
| Database | PostgreSQL (+TimescaleDB cho compliance score theo thời gian) | Một loại DB duy nhất |
| Queue | Redis (hoặc Postgres-backed queue ở MVP) | Dư sức cho quy mô 50 máy, vẫn đủ nếu mở rộng vài trăm |
| Triển khai | Docker Compose | Đủ dùng lâu dài ở quy mô ≤50 máy; chỉ cân nhắc Kubernetes nếu tương lai mở rộng vượt xa mức này — không đầu tư trước |

---

## 7. Roadmap theo giai đoạn

**Giai đoạn 0 — Nền tảng an toàn** (bắt buộc trước mọi tính năng nghiệp vụ): CA/SSH hoạt động + tách host khỏi web console; Keycloak; audit log hash-chain; Ephemeral Execution Env pipeline; Content Signing Service (3 vai trò); thiết kế xong Zero-to-CA Migration playbook; **rà soát pháp lý ban đầu** (xem rủi ro #1 mục 8) — làm song song từ ngày đầu.

**Giai đoạn 1 — Vận hành ở quy mô mục tiêu ban đầu** (tối đa 50 máy, 1–2 distro, thường 1 site): agentless qua Ansible+OpenSCAP cho 1 benchmark CIS; Control Registry với `maturity` labelling; RBAC 6 vai trò + four-eyes + dry-run/rollback bắt buộc; chạy thật Zero-to-CA Migration cho toàn bộ fleet 50 máy; **Agent tự phát triển (bản chỉ SCA/báo cáo, CHƯA bật Active Response)** cho nhóm Tier 0/1; out-of-band recovery xác minh sẵn sàng trước khi áp control Nhóm B. Đây là mục tiêu vận hành chính thức, không phải pilot cho một hệ lớn hơn.

**Giai đoạn 2 — Hoàn thiện bảo mật & mở rộng chuẩn** (vẫn trong phạm vi ≤50 máy): thêm STIG + custom TCVN/Thông tư; mở rộng RemediationVariant cho Debian; canary tự động cho control Nhóm A; **pentest riêng cho Agent, sau đó mới bật Active Response tự động remediate**. Đây là các bước hoàn thiện độ chín/bảo mật, cần làm dù có mở rộng quy mô hay không.

**Giai đoạn 3 — Mở rộng tương lai** (CHỈ triển khai nếu/khi tổ chức quyết định vượt quy mô 50 máy — không cam kết lịch trình): Local Relay/Jump-node cho multi-site; Tier 0/1/2 chính thức hóa đầy đủ hơn nếu số lượng tăng; HA control-plane (Postgres streaming replication, Kubernetes nếu thật sự cần); CA/Agent Manager có HA + break-glass riêng; enterprise RBAC/multi-tenancy; self-service access request; session recording; tích hợp SIEM/ticketing; auto-discovery/CMDB; tự động hóa đồng bộ offline content bundle theo lịch.

---

## 8. Rủi ro & đánh đổi cần người quyết định lưu ý

1. **Pháp lý có thể chặn go-live, không chỉ trễ lịch** — nếu hệ thống thuộc diện "hệ thống thông tin quan trọng về an ninh quốc gia" (Luật An ninh mạng), cần thẩm định bởi cơ quan có thẩm quyền trước khi vận hành thật; cần xác nhận việc dùng OSS nước ngoài (Keycloak/OpenBao) không vướng yêu cầu kiểm định sản phẩm ATTT trong nước, và yêu cầu lưu trữ dữ liệu trong lãnh thổ VN (Nghị định 53/2022). **Đây là quyết định cấp quản lý/pháp chế, cần làm sớm nhất, không để cuối dự án.**
2. Ephemeral Execution Env tăng độ phức tạp vận hành để đổi lấy giảm blast radius — chấp nhận được, không thể bỏ.
3. **Agent tự phát triển là hạng mục kỹ thuật rủi ro nhất dự án** (tương đương xây mini-EDR) — cần kỹ sư có kinh nghiệm crypto/network security, không có cộng đồng OSS vá lỗi hộ, cần tự pentest trước khi bật Active Response. Đây là đánh đổi có chủ đích để đội ngũ sở hữu 100% source code, nhưng cần dự trù thời gian/nhân lực nhiều hơn đáng kể so với phương án tích hợp OSS (Wazuh) đã cân nhắc ban đầu. Giới hạn quy mô xuống 50 máy giảm blast radius vận hành nhưng không giảm độ khó kỹ thuật của bài toán này.
4. Phân loại control Nhóm A/B làm chậm rollout ban đầu — cần môi trường lab đại diện cho từng distro/version.
5. Out-of-band recovery (IPMI/iLO) có thể không sẵn có trên toàn bộ máy hiện hữu — cần đầu tư bổ sung hoặc chấp nhận rủi ro cao hơn cho các máy thiếu.
6. CA/Vault là SPOF mới cho toàn bộ khả năng SSH — cần HA/backup riêng ngay từ MVP tối thiểu.
7. Cần cả đội vận hành nền tảng bảo mật chuyên trách lẫn đội phát triển web — không thể chỉ tuyển web developer thuần cho một hệ thống có bản chất sản phẩm bảo mật.
8. Zero-to-CA Migration là cửa sổ rủi ro lớn nhất — cần runbook riêng, theo batch nhỏ, không phải "làm một lần rồi quên"; máy mới thêm sau vẫn phải qua đúng quy trình.
9. **Rủi ro over-engineering ngược lại**: vì kiến trúc vẫn giữ khả năng mở rộng (Orchestrator stateless, Control Registry không khoá cứng 1 site), có thể bị cám dỗ xây sẵn HA/multi-site/K8s "phòng khi cần" — cần kỷ luật **không làm Giai đoạn 3** cho tới khi thực sự có quyết định mở rộng, nếu không MVP cho 50 máy sẽ bị trễ vì những thứ chưa cần dùng.

---

## 9. Bước tiếp theo đề xuất (sau khi thống nhất bản đề xuất này)

1. Xác nhận với bộ phận pháp lý/quản lý VNNIC về khả năng hệ thống thuộc diện quản lý an ninh mạng đặc biệt (rủi ro #1) — làm song song, không chặn kỹ thuật.
2. Đánh giá năng lực đội vận hành hiện tại (K8s? Ansible? Vault/CA?) để chốt các nhánh kỹ thuật còn mở (vd. AWX vs tự viết job-runner).
3. Scaffold repo skeleton cho Giai đoạn 0: `docker-compose.yml` (Postgres, Redis, Keycloak, OpenBao/step-ca), khung `apps/orchestrator` (FastAPI), khung `apps/web` (React), schema migration đầu tiên cho Control Registry (Control/StandardMapping/RemediationVariant).
4. Xây pilot tối thiểu trên 2–3 VM test: 1 control CIS → dry-run diff → four-eyes approve → apply → rollback, để xác thực toàn bộ pipeline an toàn trước khi mở rộng nội dung/quy mô.

**Kiểm chứng:** vì đây là giai đoạn kiến trúc/tư vấn (chưa có code), việc "verify" ở bước này là rà soát cùng đội bảo mật/pháp lý VNNIC xem các nguyên tắc ở mục 1 và 4 có khả thi trong tổ chức không, trước khi bắt tay viết code Giai đoạn 0.
