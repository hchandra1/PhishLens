from phishlens.catalog import make_signal
from phishlens.explain import build_summary, recommended_actions, sort_signals
from phishlens.models import Label


def sig(signal_id, analyzer="test"):
    return make_signal(analyzer, signal_id, "explanation", [])


def test_sorting_most_severe_first_trust_last():
    ordered = sort_signals(
        [sig("DMARC_PASS"), sig("URL_SHORTENER"), sig("DMARC_FAIL"), sig("REPLY_TO_MISMATCH")]
    )
    assert [s.id for s in ordered] == [
        "DMARC_FAIL",
        "REPLY_TO_MISMATCH",
        "URL_SHORTENER",
        "DMARC_PASS",
    ]  # noqa: E501


def test_summary_lists_top_three_reasons_as_a_sentence():
    signals = [sig(i) for i in
               ["DMARC_FAIL", "URL_SHORTENER", "LINK_TEXT_MISMATCH", "REPLY_TO_MISMATCH", "AUTH_RESULTS_MISSING"]]  # fmt: skip  # noqa: E501
    summary = build_summary(Label.PHISHING, signals, None)
    assert summary == (
        "This email is very likely a phishing attempt. It failed its sender's anti-forgery "
        "check, has a link that goes somewhere other than it says, and sends your replies to "
        "someone other than the sender (plus 1 more warning sign below)."
    )


def test_summary_uses_info_signals_only_when_nothing_else():
    summary = build_summary(Label.SUSPICIOUS, [sig("RETURN_PATH_MISMATCH")], None)
    assert "technical return address" in summary


def test_summary_includes_override_reason():
    summary = build_summary(Label.PHISHING, [sig("ATTACHMENT_RTLO_FILENAME")], "Forced because.")
    assert "Forced because." in summary


def test_safe_summary_mentions_trust_and_caveat():
    summary = build_summary(Label.SAFE, [sig("DMARC_PASS"), sig("URL_SHORTENER")], None)
    assert "passed its sender's anti-forgery check" in summary
    assert "Minor note: it uses a link-shortening service" in summary
    assert "verify it first" in summary


def test_actions_match_what_the_email_contains():
    assert recommended_actions(Label.SAFE, [], True, True) == ["No action needed."]

    phish = recommended_actions(Label.PHISHING, [sig("DMARC_FAIL")], has_links=False,
                                has_attachments=True)  # fmt: skip
    assert not any("links" in a for a in phish)
    assert any("attachments" in a for a in phish)
    assert any("Report it" in a for a in phish)

    suspicious = recommended_actions(Label.SUSPICIOUS, [sig("REPLY_TO_FREEMAIL")], False, False)
    assert suspicious[0].startswith("Don't reply")
    assert any("Verify it" in a for a in suspicious)
