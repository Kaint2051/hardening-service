"""Unit test thuần cho app/risk.py — không cần DB/HTTP, chỉ verify logic
tính điểm compliance có trọng số + luật gộp mức ưu tiên "cần chú ý"."""
from app.risk import compute_attention_level, compute_compliance_score

_HIGH_TIER_MAX = 1


# ---- compute_compliance_score ----


def test_score_none_when_no_findings():
    assert compute_compliance_score([]) is None


def test_score_100_when_all_pass():
    findings = [
        {"result": "pass", "severity": "high"},
        {"result": "pass", "severity": "low"},
    ]
    assert compute_compliance_score(findings) == 100.0


def test_score_0_when_all_fail_same_severity():
    findings = [
        {"result": "fail", "severity": "medium"},
        {"result": "fail", "severity": "medium"},
    ]
    assert compute_compliance_score(findings) == 0.0


def test_score_weighs_high_severity_failure_more_than_low():
    # 1 fail "high" (trọng số 3) + 1 pass "low" (trọng số 1) -> fail chiếm
    # 3/4 tổng trọng số -> score = 100*(1-3/4) = 25.0.
    findings = [
        {"result": "fail", "severity": "high"},
        {"result": "pass", "severity": "low"},
    ]
    assert compute_compliance_score(findings) == 25.0


def test_score_low_severity_failure_hurts_less_than_high_severity_failure():
    fail_low = compute_compliance_score(
        [{"result": "fail", "severity": "low"}, {"result": "pass", "severity": "low"}]
    )
    fail_high = compute_compliance_score(
        [{"result": "fail", "severity": "high"}, {"result": "pass", "severity": "low"}]
    )
    assert fail_low > fail_high


def test_score_ignores_info_severity_weight_but_still_has_data():
    # Toàn bộ finding severity "info" (trọng số 0) -> không None (đã có dữ
    # liệu quét thật), coi như 100 vì không có gì trọng số để fail.
    findings = [{"result": "fail", "severity": "info"}, {"result": "pass", "severity": "info"}]
    assert compute_compliance_score(findings) == 100.0


def test_score_missing_severity_defaults_like_low():
    # severity thiếu hẳn key -> .get("severity") trả None -> fallback "unknown"
    # (trọng số 1), KHÔNG bị coi trọng số 0 (không "biến mất" khỏi điểm).
    findings = [{"result": "fail"}, {"result": "pass", "severity": "low"}]
    assert compute_compliance_score(findings) == 50.0


# ---- compute_attention_level ----


def test_high_tier_not_started_ca_is_always_high_regardless_of_score():
    level = compute_attention_level(
        tier=0,
        compliance_score=100.0,  # điểm OS tuyệt đối vẫn không cứu được
        exposure="local",
        ca_migration_status="not_started",
        high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "high"


def test_low_tier_not_started_ca_does_not_force_high():
    # Tier 2 (thường) không bị luật CA ép "high" — vẫn theo ngưỡng điểm.
    level = compute_attention_level(
        tier=2,
        compliance_score=100.0,
        exposure="local",
        ca_migration_status="not_started",
        high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "low"


def test_never_scanned_high_tier_is_high():
    level = compute_attention_level(
        tier=0,
        compliance_score=None,
        exposure="local",
        ca_migration_status="migrated",
        high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "high"


def test_never_scanned_low_tier_is_medium_not_low():
    # "Chưa biết" không được coi là an toàn dù Tier thường.
    level = compute_attention_level(
        tier=2,
        compliance_score=None,
        exposure="local",
        ca_migration_status="migrated",
        high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "medium"


def test_low_tier_local_uses_loose_thresholds():
    level = compute_attention_level(
        tier=2, compliance_score=70.0, exposure="local",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "medium"  # 60 <= 70 < 85


def test_same_score_stricter_for_direct_exposure_host():
    local = compute_attention_level(
        tier=2, compliance_score=70.0, exposure="local",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    direct = compute_attention_level(
        tier=2, compliance_score=70.0, exposure="direct",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert local == "medium"
    assert direct == "high"  # ngưỡng high_cut=85 cho "direct", 70 < 85


def test_proxied_exposure_stricter_than_local_at_same_score():
    # Điểm 70: "local" (high_cut=60) không rơi vào "high" (70 >= 60) -> medium
    # (70 < 85). "proxied" (high_cut=75) rơi vào "high" vì 70 < 75.
    local = compute_attention_level(
        tier=2, compliance_score=70.0, exposure="local",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    proxied = compute_attention_level(
        tier=2, compliance_score=70.0, exposure="proxied",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert local == "medium"
    assert proxied == "high"


def test_proxied_exposure_looser_than_direct_at_same_score():
    # Điểm 80: "proxied" (high_cut=75, medium_cut=90) không rơi vào "high"
    # (80 >= 75) -> medium (80 < 90). "direct" (high_cut=85) rơi vào "high"
    # vì 80 < 85 — xác nhận "proxied" thật sự nằm GIỮA "local" và "direct",
    # không trùng ngưỡng với đầu nào.
    proxied = compute_attention_level(
        tier=2, compliance_score=80.0, exposure="proxied",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    direct = compute_attention_level(
        tier=2, compliance_score=80.0, exposure="direct",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert proxied == "medium"
    assert direct == "high"


def test_same_score_stricter_for_high_tier_host():
    normal_tier = compute_attention_level(
        tier=2, compliance_score=90.0, exposure="local",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    high_tier = compute_attention_level(
        tier=1, compliance_score=90.0, exposure="local",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert normal_tier == "low"        # 90 >= 85 (ngưỡng thường)
    assert high_tier == "medium"       # 90 < 95 (ngưỡng khắt khe cho Tier cao)


def test_high_tier_forces_strict_threshold_even_when_local():
    # Tier cao dùng ngưỡng khắt khe nhất (85/95) BẤT KỂ exposure — khớp luật 3
    # (app/risk.py): "tier <= high_tier_max HOẶC exposure == direct".
    level = compute_attention_level(
        tier=0, compliance_score=80.0, exposure="local",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "high"  # 80 < 85


def test_perfect_score_is_always_low_even_when_strict():
    level = compute_attention_level(
        tier=0, compliance_score=100.0, exposure="direct",
        ca_migration_status="migrated", high_tier_max=_HIGH_TIER_MAX,
    )
    assert level == "low"
