from dracxx.engines.vulnerability.confidence import score_confidence
from dracxx.models.schema import Confidence


def test_confirmed_confidence():
    c = score_confidence(True, True, 2, True, True, True)
    assert c == Confidence.CONFIRMED_NON_DESTRUCTIVE


def test_low_confidence():
    c = score_confidence(False, False, 0, False, False, False)
    assert c == Confidence.INFO
