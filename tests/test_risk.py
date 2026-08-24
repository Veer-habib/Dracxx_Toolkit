from dracxx.engines.risk.engine import compute_risk_score, risk_band
from dracxx.models.schema import Confidence


def test_risk_score_high_with_kev():
    score = compute_risk_score(
        cvss_score=9.8, epss_score=0.9, kev=True,
        internet_exposed=True, confidence=Confidence.HIGH_CONFIDENCE,
    )
    assert score > 70
    assert risk_band(score) in ("HIGH", "CRITICAL")


def test_risk_score_low_without_kev():
    score = compute_risk_score(
        cvss_score=2.0, epss_score=0.01, kev=False,
        internet_exposed=False, confidence=Confidence.POTENTIAL,
    )
    assert score < 30


def test_risk_band_thresholds():
    assert risk_band(90) == "CRITICAL"
    assert risk_band(65) == "HIGH"
    assert risk_band(40) == "MEDIUM"
    assert risk_band(20) == "LOW"
    assert risk_band(5) == "INFO"
