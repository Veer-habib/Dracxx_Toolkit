from dracxx.correlation.dedup import deduplicate
from dracxx.models.schema import Finding, Severity, Confidence


def _f(**kw):
    base = dict(finding_id="F1", title="t", severity=Severity.LOW,
                confidence=Confidence.INFO, target="x", asset="x", scanner="nmap")
    base.update(kw)
    return Finding(**base)


def test_dedup_merges_same_asset_port():
    a = _f(finding_id="A", port=80, scanner="nmap")
    b = _f(finding_id="B", port=80, scanner="nuclei")
    merged = deduplicate([a, b])
    assert len(merged) == 1
    assert "nmap" in merged[0].scanner and "nuclei" in merged[0].scanner


def test_dedup_keeps_distinct_ports():
    a = _f(finding_id="A", port=80)
    b = _f(finding_id="B", port=443)
    merged = deduplicate([a, b])
    assert len(merged) == 2
