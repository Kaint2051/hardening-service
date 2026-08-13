"""Tổng hợp "cần chú ý" cho fleet (mục thảo luận với người dùng: Tier chỉ nên
là "mức độ quan trọng dịch vụ", KHÔNG gộp "mức độ hardening" vào — 2 trục đổi
tốc độ khác nhau) — Tier × điểm compliance có trọng số theo severity ×
exposure (local/proxied/direct) × ca_migration_status, gộp thành 1 mức ưu
tiên dễ đọc thay vì phải tự so nhiều màn hình rời rạc.

Cố tình dùng luật IF/ELSE có THỨ TỰ rõ ràng (luật đứng trước thắng), KHÔNG
phải 1 công thức cộng điểm mờ — dễ audit/giải thích cho 1 công cụ bảo mật,
đúng tinh thần "mọi quyết định phải giải thích được" xuyên suốt dự án này.

Module này KHÔNG đụng DB/FastAPI — nhận dữ liệu đã có sẵn (list[dict] findings,
vài field của Host), để unit test được toàn bộ logic mà không cần DB thật.
"""
from typing import Literal, Optional

AttentionLevel = Literal["high", "medium", "low"]

# Thang severity chuẩn XCCDF (unknown/info/low/medium/high) — xem
# apps/execution-env/scan.sh: rr.get("severity", "unknown"). "info" không
# tính là rủi ro thật (trọng số 0); "unknown" (nội dung SCAP thiếu severity)
# xử lý như "low" (trọng số 1) — KHÔNG bỏ qua hẳn (trọng số 0), tránh 1 rule
# thiếu severity vô tình "biến mất" khỏi điểm tổng mà không ai để ý.
SEVERITY_WEIGHTS: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "unknown": 1,
}


def compute_compliance_score(findings: list[dict]) -> Optional[float]:
    """Điểm compliance có trọng số theo severity, 0-100 (100 = không có rule
    trọng số nào fail). Trả `None` nếu KHÔNG có finding nào (chưa quét lần
    nào, hoặc job quét không parse được kết quả) — PHẢI phân biệt rõ với
    100.0 (đã quét thật, mọi thứ đạt): "chưa biết" khác hẳn "biết là tốt",
    xem compute_attention_level dùng sự khác biệt này thế nào.

    Chỉ nhận đúng field `result` ("pass"/"fail") và `severity` — khớp đúng
    schema `Finding` (app/schemas.py) mà scan.sh/apps/agent xuất ra.
    """
    weighted = [
        (f.get("result"), SEVERITY_WEIGHTS.get(f.get("severity") or "unknown", 1))
        for f in findings
    ]
    if not weighted:
        return None
    total = sum(w for _, w in weighted)
    if total == 0:
        # Mọi rule đều severity "info" (trọng số 0) — không có gì để tính
        # theo trọng số, nhưng ĐÃ có dữ liệu quét thật (khác None ở trên).
        return 100.0
    failed = sum(w for result, w in weighted if result == "fail")
    return round(100.0 * (1 - failed / total), 1)


def compute_attention_level(
    tier: int,
    compliance_score: Optional[float],
    exposure: str,
    ca_migration_status: str,
    high_tier_max: int,
) -> AttentionLevel:
    """Mức ưu tiên cần xử lý — luật có THỨ TỰ, luật đứng trước thắng:

    1. Máy Tier cao (`tier <= high_tier_max`) còn dùng SSH key/password tĩnh
       (`ca_migration_status == "not_started"`) -> LUÔN "high", bất kể điểm
       compliance OS ra sao. Rủi ro lộ credential tĩnh độc lập hoàn toàn với
       việc OS đã hardening tốt hay chưa.
    2. Chưa có lần quét thành công nào (`compliance_score is None`) —
       "không biết" KHÔNG được coi là an toàn: "high" cho Tier cao, "medium"
       cho Tier thường (2).
    3. Có điểm — ngưỡng khắt khe hơn (high_cut/medium_cut cao hơn) theo đúng
       thứ tự rủi ro của `exposure` (app/schemas.py:EXPOSURE_LEVELS): máy
       Tier cao HOẶC "direct" (expose thẳng, không lớp chặn) dùng ngưỡng
       khắt khe nhất; "proxied" (có lớp trung gian — reverse proxy/WAF/LB)
       dùng ngưỡng giữa; còn lại ("local", Tier thường) dùng ngưỡng lỏng
       nhất — 1 lỗi nhỏ trên máy càng lộ ra ngoài/càng quan trọng vẫn đáng lo
       hơn máy nội bộ ít quan trọng có cùng điểm số.
    """
    if tier <= high_tier_max and ca_migration_status == "not_started":
        return "high"
    if compliance_score is None:
        return "high" if tier <= high_tier_max else "medium"

    if exposure == "direct" or tier <= high_tier_max:
        high_cut, medium_cut = 85.0, 95.0
    elif exposure == "proxied":
        high_cut, medium_cut = 75.0, 90.0
    else:
        high_cut, medium_cut = 60.0, 85.0

    if compliance_score < high_cut:
        return "high"
    if compliance_score < medium_cut:
        return "medium"
    return "low"


# Thứ tự ưu tiên hiển thị (0 = nổi lên đầu danh sách) — dùng để sort response
# GET /hosts/risk-overview, xem app/hosts.py.
ATTENTION_SORT_RANK: dict[AttentionLevel, int] = {"high": 0, "medium": 1, "low": 2}
