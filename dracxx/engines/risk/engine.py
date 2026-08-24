"""Documented weighted/rules-based risk model.

Risk is NOT simply CVSS + EPSS. It's a weighted combination of severity,
exploitation likelihood, known-exploited status, exposure, and detection
confidence, each contributing a bounded share of a 0-100 score.

Weights (sum to 100):
  CVSS severity        : 35
  EPSS likelihood       : 20
  CISA KEV boost        : 20 (flat bonus if present, capped)
  Internet exposure      : 10
  Detection confidence   : 10
  Auth requirement        : 5 (lower risk if auth required)
"""
from __future__ import annotations

from dracxx.models.schema import Confidence

CONFIDENCE_WEIGHT = {
    Confidence.INFO: 0.2,
    Confidence.POTENTIAL: 0.4,
    Confidence.LIKELY: 0.65,
    Confidence.HIGH_CONFIDENCE: 0.85,
    Confidence.CONFIRMED_NON_DESTRUCTIVE: 1.0,
}


def compute_risk_score(
    cvss_score: float | None,
    epss_score: float | None,
    kev: bool,
    internet_exposed: bool,
    confidence: Confidence,
    requires_auth: bool = False,
) -> float:
    cvss_component = (cvss_score / 10.0) * 35 if cvss_score else 0.0
    epss_component = (epss_score or 0.0) * 20
    kev_component = 20.0 if kev else 0.0
    exposure_component = 10.0 if internet_exposed else 4.0
    confidence_component = CONFIDENCE_WEIGHT.get(confidence, 0.3) * 10
    auth_penalty = -5.0 if requires_auth else 0.0

    score = (cvss_component + epss_component + kev_component +
             exposure_component + confidence_component + auth_penalty)
    return round(max(0.0, min(100.0, score)), 1)


def risk_band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"
