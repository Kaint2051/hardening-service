"""Control Templates — duyệt + chọn rule từ nội dung chuẩn CHÍNH THỨC
(ComplianceAsCode/CIS Benchmark — CÙNG nguồn nội dung đang dùng cho tính
năng "Quét" qua OpenSCAP) để tạo Control mới, thay cho việc tự tay trích/
ghép YAML qua SSH mỗi lần (xem lịch sử tạo Control
"cis-ubuntu-22-04-benchmark-v2-0-0-ssh-controls-level-1-server" — làm thủ
công 1 lần bằng sed/grep, giờ tự động hoá phần duyệt+chọn+ghép).

CỐ Ý KHÔNG tự động hoá bước ký nội dung — endpoint create-control ở đây chỉ
tạo Control (draft) + StandardMapping, trả về playbook.yml đã ghép để
operator TỰ đưa qua đúng quy trình 3 vai trò
(scripts/content-signing/{pull,review,sign}.sh) rồi mới tạo RemediationVariant
trỏ tới bundle đã ký — xem apps/execution-env/README.md mục "Trước khi dùng
thật". Bỏ qua bước người thật ký duyệt sẽ phá vỡ đúng nguyên tắc "3 vai trò
độc lập" toàn dự án đang theo.

Định dạng nguồn: 1 file playbook Ansible do ComplianceAsCode TỰ SINH cho 1
product+profile (tải qua scripts/content-signing/pull.sh từ release chính
thức, xem control-templates/README.md) — luôn có cấu trúc cố định: 1 play,
`vars:` dùng chung, `tasks:` là danh sách PHẲNG (không nhóm theo rule tường
minh). Mỗi rule XCCDF thật ra là NHIỀU task liền kề dùng CHUNG đúng 1 tag
dạng snake_case (vd "sshd_disable_root_login") — các tag còn lại là tham
chiếu chuẩn khác (NIST/CJIS/PCI-DSS/DISA-STIG) hoặc mô tả mức độ nghiêm
trọng/độ khó/mức gây gián đoạn. KHÔNG có field "rule_id" tường minh trong
format này — heuristic phân loại tag dưới đây (_is_rule_id_tag) đã verify
thật trên file CIS Ubuntu 22.04 (298/298 rule phân loại đúng, 0 lỗi, xem
lịch sử làm việc).
"""
import os
import re
from dataclasses import dataclass, field

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import CurrentUser
from app.config import settings
from app.controls import add_standard_mapping, create_control
from app.db import SessionLocal
from app.permissions import CONTROL_TEMPLATES_EDIT, CONTROL_TEMPLATES_VIEW
from app.rbac import require_permission
from app.schemas import (
    ControlCreate,
    ControlTemplateCreateRequest,
    ControlTemplateCreateResponse,
    ControlTemplateOut,
    ControlTemplatePreviewRequest,
    ControlTemplatePreviewResponse,
    ControlTemplateRuleOut,
    StandardMappingCreate,
)

router = APIRouter(prefix="/control-templates", tags=["control-templates"])

_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _get_db():
    # Cùng SessionLocal với app/controls.py (không phải cùng 1 hàm generator
    # — mỗi module giữ generator riêng theo đúng quy ước Depends() hiện có
    # trong toàn bộ codebase, xem app/hosts.py, app/jobs.py... đều tự khai
    # _get_db riêng thay vì import chung 1 hàm).
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_FRAMEWORK_TAG_PREFIXES = (
    "NIST-", "CJIS-", "PCI-DSS", "DISA-STIG-", "srg_", "anssi_", "hipaa_",
    "stigid_", "cis-", "cis_",
)
_GENERIC_TAGS = frozenset(
    {
        "always",
        "low_complexity", "medium_complexity", "high_complexity",
        "low_disruption", "medium_disruption", "high_disruption",
        "low_severity", "medium_severity", "high_severity", "unknown_severity",
        "no_reboot_needed", "reboot_needed",
        "restrict_strategy", "disable_strategy", "enable_strategy",
        "configure_strategy", "unknown_strategy", "patch_strategy",
    }
)
_SEVERITY_TAGS = {"low_severity": "low", "medium_severity": "medium", "high_severity": "high", "unknown_severity": "unknown"}
_COMPLEXITY_TAGS = {"low_complexity": "low", "medium_complexity": "medium", "high_complexity": "high"}
_DISRUPTION_TAGS = {"low_disruption": "low", "medium_disruption": "medium", "high_disruption": "high"}


def _is_rule_id_tag(tag: str) -> bool:
    if tag in _GENERIC_TAGS:
        return False
    return not any(tag.startswith(p) for p in _FRAMEWORK_TAG_PREFIXES)


# {{ tên_biến }} hoặc {{ tên_biến | filter_gì_đó }} — chỉ quan tâm TÊN biến
# đầu tiên trong biểu thức, không cần parse Jinja đầy đủ.
_JINJA_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)")


@dataclass
class _ParsedRule:
    rule_id: str
    title: str
    order_index: int
    severity: str | None = None
    complexity: str | None = None
    disruption: str | None = None
    compliance_refs: list[str] = field(default_factory=list)
    task_count: int = 0
    variables: dict[str, str] = field(default_factory=dict)


@dataclass
class _ParsedTemplate:
    title: str
    header_text: str  # từ đầu file tới hết "  vars:" block, gồm cả "  tasks:"
    vars_dict: dict  # vars: đã parse thành dict thật (không phải text thô)
    prereq_task_texts: list[str]  # task tag "always", đã loại trùng theo name
    rules: dict[str, _ParsedRule]
    rule_order: list[str]
    task_texts: dict[str, str]


_TEMPLATE_CACHE: dict[str, _ParsedTemplate] = {}


def _template_path(template_id: str) -> str:
    # Chặn path traversal — template_id ghép thẳng vào tên file trong
    # settings.control_templates_dir, chỉ cho phép ký tự an toàn.
    if not _ID_RE.match(template_id):
        raise HTTPException(status_code=404, detail="template không tồn tại")
    path = os.path.join(settings.control_templates_dir, f"{template_id}.yml")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="template không tồn tại")
    return path


def _extract_title(first_lines: list[str], fallback: str) -> str:
    # Dòng comment dạng "# Ansible Playbook for CIS Ubuntu Linux 22.04 LTS
    # Benchmark for Level 1 - Server" (dễ đọc hơn nhiều so với Profile ID
    # dạng xccdf_org.ssgproject...) — nếu không tìm thấy, dùng tên file.
    for line in first_lines:
        m = re.match(r"^#\s*Ansible Playbook for (.+)$", line.strip())
        if m:
            return m.group(1).strip()
    return fallback


def _parse_template(template_id: str) -> _ParsedTemplate:
    if template_id in _TEMPLATE_CACHE:
        return _TEMPLATE_CACHE[template_id]
    path = _template_path(template_id)
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    tasks_line_idx = next((i for i, line in enumerate(lines) if line.rstrip("\n") == "  tasks:"), None)
    if tasks_line_idx is None:
        raise HTTPException(
            status_code=500,
            detail=f"template '{template_id}' không đúng định dạng (thiếu dòng 'tasks:') — xem control-templates/README.md",
        )
    header_text = "".join(lines[: tasks_line_idx + 1])
    title = _extract_title(lines[:30], fallback=template_id)

    # header_text tự nó là 1 YAML hợp lệ (list 1 phần tử: play, "tasks:" chưa
    # có gì bên dưới nên parse thành None, không lỗi) — parse thẳng để lấy
    # vars: thành dict thật, không cần tự cắt dòng/tự thụt lề tay.
    try:
        parsed_header = yaml.safe_load(header_text)
        vars_dict = parsed_header[0].get("vars") or {} if isinstance(parsed_header, list) and parsed_header else {}
    except yaml.YAMLError:
        vars_dict = {}
    if not isinstance(vars_dict, dict):
        vars_dict = {}

    task_starts = [i for i in range(tasks_line_idx + 1, len(lines)) if re.match(r"^  - name:", lines[i])]
    task_starts.append(len(lines))

    rules: dict[str, _ParsedRule] = {}
    rule_order: list[str] = []
    task_texts: dict[str, list[str]] = {}
    prereq_seen: set[str] = set()
    prereq_task_texts: list[str] = []

    for idx in range(len(task_starts) - 1):
        start, end = task_starts[idx], task_starts[idx + 1]
        raw = "".join(lines[start:end])
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError:
            continue  # task không parse được riêng lẻ (hiếm) -- bỏ qua, không chặn cả template
        if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
            continue
        task = parsed[0]
        name = str(task.get("name") or "").strip()
        tags = task.get("tags")
        if not isinstance(tags, list):
            continue

        if tags == ["always"]:
            if name not in prereq_seen:
                prereq_seen.add(name)
                prereq_task_texts.append(raw)
            continue

        rule_tags = [t for t in tags if isinstance(t, str) and _is_rule_id_tag(t)]
        if not rule_tags:
            continue
        rid = rule_tags[0]

        if rid not in rules:
            rule_order.append(rid)
            rules[rid] = _ParsedRule(rule_id=rid, title=name, order_index=len(rule_order) - 1)
            task_texts[rid] = []
        r = rules[rid]
        if name and (not r.title or len(name) < len(r.title)):
            r.title = name  # task chính (không có hậu tố " - ...") thường có tên ngắn nhất
        r.task_count += 1
        for t in tags:
            if not isinstance(t, str) or t == rid or t in _GENERIC_TAGS:
                continue
            if not _is_rule_id_tag(t) and t not in r.compliance_refs:
                r.compliance_refs.append(t)
        for tag_name, val in _SEVERITY_TAGS.items():
            if tag_name in tags:
                r.severity = val
        for tag_name, val in _COMPLEXITY_TAGS.items():
            if tag_name in tags:
                r.complexity = val
        for tag_name, val in _DISRUPTION_TAGS.items():
            if tag_name in tags:
                r.disruption = val
        task_texts[rid].append(raw)

    joined_task_texts = {rid: "".join(texts) for rid, texts in task_texts.items()}

    # Biến rule THẬT SỰ dùng — quét {{ tên_biến }} trong đúng task của rule
    # đó, đối chiếu với vars_dict (bỏ qua tên trùng biến vòng lặp nội bộ như
    # "item" vì KHÔNG có trong vars_dict của template).
    for rid, r in rules.items():
        referenced = set(_JINJA_VAR_RE.findall(joined_task_texts[rid]))
        r.variables = {name: str(vars_dict[name]) for name in referenced if name in vars_dict}

    parsed_template = _ParsedTemplate(
        title=title,
        header_text=header_text,
        vars_dict=vars_dict,
        prereq_task_texts=prereq_task_texts,
        rules=rules,
        rule_order=rule_order,
        task_texts=joined_task_texts,
    )
    _TEMPLATE_CACHE[template_id] = parsed_template
    return parsed_template


def _list_template_ids() -> list[str]:
    try:
        names = os.listdir(settings.control_templates_dir)
    except OSError:
        return []
    return sorted(n[:-4] for n in names if n.endswith(".yml"))


@router.get("", response_model=list[ControlTemplateOut])
def list_control_templates(
    _user: CurrentUser = Depends(require_permission(CONTROL_TEMPLATES_VIEW)),
) -> list[ControlTemplateOut]:
    out = []
    for template_id in _list_template_ids():
        parsed = _parse_template(template_id)
        out.append(ControlTemplateOut(id=template_id, title=parsed.title, rule_count=len(parsed.rule_order)))
    return out


@router.get("/{template_id}/rules", response_model=list[ControlTemplateRuleOut])
def list_template_rules(
    template_id: str,
    q: str | None = None,
    _user: CurrentUser = Depends(require_permission(CONTROL_TEMPLATES_VIEW)),
) -> list[ControlTemplateRuleOut]:
    parsed = _parse_template(template_id)
    needle = (q or "").strip().lower()
    out = []
    for rid in parsed.rule_order:
        r = parsed.rules[rid]
        if needle and needle not in rid.lower() and needle not in r.title.lower():
            continue
        out.append(
            ControlTemplateRuleOut(
                rule_id=r.rule_id,
                title=r.title,
                severity=r.severity,
                complexity=r.complexity,
                disruption=r.disruption,
                compliance_refs=r.compliance_refs,
                task_count=r.task_count,
                variables=r.variables,
            )
        )
    return out


def _assemble_playbook(parsed: _ParsedTemplate, rule_ids: list[str]) -> str:
    unknown = [rid for rid in rule_ids if rid not in parsed.rules]
    if unknown:
        raise HTTPException(status_code=422, detail=f"rule_id không tồn tại trong template: {unknown}")
    # Giữ ĐÚNG thứ tự xuất hiện trong file gốc (không theo thứ tự người dùng
    # chọn) — 1 vài rule có thể phụ thuộc biến/thứ tự task của rule đứng
    # trước trong file gốc, dù hiếm.
    ordered = sorted(set(rule_ids), key=lambda rid: parsed.rules[rid].order_index)
    parts = [parsed.header_text]
    parts.extend(parsed.prereq_task_texts)
    for rid in ordered:
        parts.append(parsed.task_texts[rid])
    return "".join(parts)


@router.post("/{template_id}/preview", response_model=ControlTemplatePreviewResponse)
def preview_template_playbook(
    template_id: str,
    body: ControlTemplatePreviewRequest,
    _user: CurrentUser = Depends(require_permission(CONTROL_TEMPLATES_EDIT)),
) -> ControlTemplatePreviewResponse:
    parsed = _parse_template(template_id)
    playbook_yaml = _assemble_playbook(parsed, body.rule_ids)
    return ControlTemplatePreviewResponse(playbook_yaml=playbook_yaml)


def _split_compliance_ref(ref: str) -> tuple[str, str]:
    """Tách 1 tag tham chiếu chuẩn (vd "NIST-800-53-CM-6(a)") thành
    (standard, section_id) best-effort — cắt phần cuối cùng trông giống mã
    section (chữ/số/dấu chấm/ngoặc) khỏi phần đầu (tên chuẩn). KHÔNG hoàn hảo
    cho mọi định dạng nhưng đủ dùng để tự động điền StandardMapping thay vì
    bắt operator gõ tay lại 3 field cho từng tag — operator vẫn xem/sửa lại
    được trước khi Control thật sự tạo (xem preview trước khi create-control).
    """
    m = re.match(r"^(.*?)-([A-Za-z0-9.()]+)$", ref)
    if m:
        return m.group(1)[:32], m.group(2)[:64]
    return ref[:32], ""


@router.post(
    "/{template_id}/create-control",
    response_model=ControlTemplateCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_control_from_template(
    template_id: str,
    body: ControlTemplateCreateRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(CONTROL_TEMPLATES_EDIT)),
) -> ControlTemplateCreateResponse:
    """Tạo Control (draft) + StandardMapping tự động suy ra từ tag tham
    chiếu chuẩn (NIST/CJIS/PCI-DSS/DISA-STIG...) của các rule đã chọn. KHÔNG
    tạo RemediationVariant, KHÔNG ký gì — trả nguyên `playbook_yaml` (có thể
    đã bị operator sửa tay so với bản preview ban đầu, dùng ĐÚNG bản họ gửi
    lên, không re-assemble lại từ rule_ids) để operator tự lưu + đưa qua
    scripts/content-signing/{pull,review,sign}.sh, rồi mới tạo
    RemediationVariant trỏ bundle đã ký qua API sẵn có
    (POST /controls/{id}/remediation-variants) — xem docstring module này.
    """
    parsed = _parse_template(template_id)
    unknown = [rid for rid in body.rule_ids if rid not in parsed.rules]
    if unknown:
        raise HTTPException(status_code=422, detail=f"rule_id không tồn tại trong template: {unknown}")

    control = create_control(
        body=ControlCreate(title=body.title, description=body.description, category=body.category),
        db=db,
        user=user,
    )

    # Hợp nhất biến của MỌI rule đã chọn — hiển thị cho người tạo Control biết
    # playbook này dùng biến gì để đặt giá trị ngay trong template (đường
    # override riêng theo host đã bị gỡ, xem app/models.py:
    # Host.ansible_var_overrides).
    overridable_variables: dict[str, str] = {}
    for rid in body.rule_ids:
        overridable_variables.update(parsed.rules[rid].variables)
    if overridable_variables:
        control.overridable_variables = overridable_variables
        db.commit()

    compliance_refs: list[str] = []
    for rid in body.rule_ids:
        for ref in parsed.rules[rid].compliance_refs:
            if ref not in compliance_refs:
                compliance_refs.append(ref)

    mappings_added = 0
    for ref in compliance_refs:
        standard, section_id = _split_compliance_ref(ref)
        if not standard:
            continue
        try:
            add_standard_mapping(
                control_id=control.id,
                body=StandardMappingCreate(
                    standard=standard,
                    standard_version=template_id,
                    section_id=section_id or ref[:64],
                    reference_url=None,
                ),
                db=db,
                user=user,
            )
            mappings_added += 1
        except HTTPException as exc:
            if exc.status_code != 409:  # standard mapping trùng -- bỏ qua, không phải lỗi thật
                raise

    # Cầu nối rule_id <-> control_id cho GET /controls/lookup (app/controls.py)
    # — TÁCH RIÊNG khỏi vòng lặp compliance_refs ở trên có chủ đích: vòng đó
    # dedup theo REF dùng chung cho nhiều rule (1 ref NIST có thể xuất hiện ở
    # 2 rule khác nhau, chỉ tạo 1 mapping), nên KHÔNG thể gắn cis_rule_id vào
    # đúng 1 rule cụ thể một cách an toàn ở đó — rule thứ 2 chia sẻ ref với
    # rule thứ 1 sẽ bị "che khuất" (dedup bỏ qua), mất luôn cầu nối. Ở đây,
    # mỗi rule_id LUÔN có ĐÚNG 1 dòng ghi riêng, standard="CIS-RULE-ID" là
    # giá trị đánh dấu nội bộ (không phải 1 chuẩn tuân thủ thật hiển thị cho
    # người dùng cuối), không tính vào standard_mappings_added trả về (đó là
    # số mapping CHUẨN THẬT tự suy ra, không phải bookkeeping nội bộ này).
    for rid in body.rule_ids:
        try:
            add_standard_mapping(
                control_id=control.id,
                body=StandardMappingCreate(
                    standard="CIS-RULE-ID",
                    standard_version=template_id,
                    section_id=rid,
                    reference_url=None,
                    cis_rule_id=rid,
                ),
                db=db,
                user=user,
            )
        except HTTPException as exc:
            if exc.status_code != 409:
                raise

    return ControlTemplateCreateResponse(
        control_id=control.id,
        standard_mappings_added=mappings_added,
        playbook_yaml=body.playbook_yaml,
        overridable_variables=overridable_variables,
    )
