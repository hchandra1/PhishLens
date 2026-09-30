import dataclasses

import pytest

from phishlens.catalog import make_signal
from phishlens.models import Label
from phishlens.scoring import Override, load_scoring_config, score_signals


def sig(signal_id, analyzer="test"):
    return make_signal(analyzer, signal_id, "explanation", [])


def test_no_signals_is_safe():
    result = score_signals([])
    assert (result.label, result.score, result.override) == (Label.SAFE, 0, None)


@pytest.mark.parametrize(
    ("ids", "label"),
    [
        (["RETURN_PATH_MISMATCH", "AUTH_RESULTS_MISSING"], Label.SAFE),  # 8
        (["LINK_TEXT_MISMATCH"], Label.SUSPICIOUS),  # one strong signal: 25
        (["DMARC_FAIL", "LINK_TEXT_MISMATCH"], Label.PHISHING),  # two strong signals: 60
    ],
)
def test_thresholds(ids, label):
    assert score_signals([sig(i) for i in ids]).label == label


def test_score_is_clamped_to_0_100():
    assert score_signals([sig("DMARC_PASS")]).score == 0
    many = ["DMARC_FAIL", "SENDER_DOMAIN_LOOKALIKE", "URL_BRAND_LOOKALIKE", "LINK_TEXT_MISMATCH"]
    assert score_signals([sig(i) for i in many]).score == 100


def test_trust_signal_lowers_score_when_nothing_serious():
    result = score_signals([sig("DMARC_PASS"), sig("URL_SHORTENER"), sig("REPLY_TO_MISMATCH")])
    assert result.score == 3  # 8 + 10 - 15
    assert result.label == Label.SAFE


def test_trust_signal_ignored_when_high_severity_present():
    # An attacker can pass DMARC on their own look-alike domain.
    result = score_signals([sig("DMARC_PASS"), sig("SENDER_DOMAIN_LOOKALIKE")])
    assert result.score == 35
    assert "DMARC_PASS" not in {s.id for s in result.counted}


def test_trust_discount_can_be_disabled():
    config = dataclasses.replace(load_scoring_config(), ignore_trust_when_high_severity=False)
    assert score_signals([sig("DMARC_PASS"), sig("SENDER_DOMAIN_LOOKALIKE")], config).score == 20


def test_override_forces_label_and_lifts_score():
    result = score_signals([sig("ATTACHMENT_RTLO_FILENAME")])  # weight 40, below phishing
    assert result.label == Label.PHISHING
    assert result.score == 50
    assert "disguises its real file type" in result.override


def test_override_not_reported_when_score_already_reaches_label():
    ids = ["ATTACHMENT_DOUBLE_EXTENSION", "DMARC_FAIL"]
    result = score_signals([sig(i) for i in ids])
    assert result.label == Label.PHISHING and result.override is None


def test_config_validation():
    config = load_scoring_config()
    with pytest.raises(ValueError, match="thresholds"):
        dataclasses.replace(config, suspicious_threshold=60)
    with pytest.raises(ValueError, match="unknown signals"):
        dataclasses.replace(
            config, overrides=(Override(Label.PHISHING, frozenset({"NOT_A_SIGNAL"}), "x"),)
        )
