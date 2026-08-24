from dracxx.utils.version import compare_versions, evaluate_affected, MatchStatus, VersionRange


def test_compare_versions_basic():
    assert compare_versions("1.2.3", "1.2.4") < 0
    assert compare_versions("2.0.0", "1.9.9") > 0
    assert compare_versions("1.0.0", "1.0.0") == 0


def test_version_range_contains():
    rng = VersionRange.parse(">=2.0.0 and <2.4.15")
    assert rng.contains("2.4.10")
    assert not rng.contains("2.5.0")
    assert not rng.contains("1.9.0")


def test_evaluate_affected_matches():
    status = evaluate_affected("2.4.10", [">=2.0.0 and <2.4.15"])
    assert status == MatchStatus.AFFECTED


def test_evaluate_affected_not_matched():
    status = evaluate_affected("2.5.0", [">=2.0.0 and <2.4.15"])
    assert status == MatchStatus.NOT_AFFECTED


def test_evaluate_affected_unknown_version():
    status = evaluate_affected(None, [">=2.0.0 and <2.4.15"])
    assert status == MatchStatus.UNKNOWN_VERSION


def test_evaluate_affected_no_ranges():
    status = evaluate_affected("1.0.0", [])
    assert status == MatchStatus.POTENTIALLY_AFFECTED


def test_evaluate_affected_fixed():
    status = evaluate_affected("3.0.0", [">=2.0.0 and <2.4.15"], fixed_versions=["2.4.15"])
    assert status == MatchStatus.FIXED
