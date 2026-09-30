import threading
from pathlib import Path

import pytest

from phishlens.catalog import make_signal
from phishlens.engine import analyze, analyze_raw
from phishlens.models import AnalyzerStatus, AnalyzerUnavailable, Label, ParsedEmail

FIXTURES = Path(__file__).parent / "fixtures"
OPT_IN = {"llm", "domain_age", "safe_browsing", "virustotal"}


class Fixed:
    def __init__(self, name, *ids):
        self.name, self.ids = name, ids

    def analyze(self, email):
        return [make_signal(self.name, i, f"{i} found.", []) for i in self.ids]


class Broken:
    name = "broken"

    def analyze(self, email):
        raise RuntimeError("secret internal detail")


class Unavailable:
    name = "llm"

    def analyze(self, email):
        raise AnalyzerUnavailable("No API key configured.")


class Hangs:
    name = "slow"

    def __init__(self):
        self.release = threading.Event()

    def analyze(self, email):
        self.release.wait(5)
        return []


@pytest.mark.parametrize(
    ("fixture", "label"),
    [
        ("01_plain_text.eml", Label.SAFE),
        ("02_multipart_alternative.eml", Label.PHISHING),
        ("03_encoded_headers.eml", Label.SUSPICIOUS),
        ("04_html_only.eml", Label.PHISHING),
        ("05_attachments.eml", Label.PHISHING),
        ("06_inline_image.eml", Label.SAFE),
        ("07_forwarded_attachment.eml", Label.SAFE),
        ("08_unknown_charset.eml", Label.SAFE),
        ("09_mbox_crlf.eml", Label.PHISHING),
    ],
)
def test_fixture_verdicts(fixture, label):
    verdict = analyze_raw((FIXTURES / fixture).read_bytes())
    assert verdict.label == label
    statuses = {r.analyzer: r.status for r in verdict.analyzers}
    for optional in OPT_IN:  # need network or credentials; off in tests
        assert statuses.pop(optional) == AnalyzerStatus.UNAVAILABLE
    assert set(statuses.values()) == {AnalyzerStatus.OK}
    assert verdict.summary and verdict.recommended_actions


def test_verdict_is_assembled_from_all_analyzers():
    email = ParsedEmail()
    verdict = analyze(email, [Fixed("a", "URL_SHORTENER"), Fixed("b", "DMARC_FAIL")])
    assert [s.id for s in verdict.signals] == ["DMARC_FAIL", "URL_SHORTENER"]  # sorted
    assert verdict.score == 43 and verdict.label == Label.SUSPICIOUS
    assert [r.analyzer for r in verdict.analyzers] == ["a", "b"]


def test_crashing_analyzer_does_not_block_verdict_or_leak_details():
    verdict = analyze(ParsedEmail(), [Broken(), Fixed("ok", "LINK_TEXT_MISMATCH")])
    assert verdict.label == Label.SUSPICIOUS
    report = next(r for r in verdict.analyzers if r.analyzer == "broken")
    assert report.status == AnalyzerStatus.ERROR
    assert "secret" not in report.detail


def test_unavailable_analyzer_is_reported_with_its_reason():
    verdict = analyze(ParsedEmail(), [Unavailable()])
    (report,) = verdict.analyzers
    assert report.status == AnalyzerStatus.UNAVAILABLE
    assert report.detail == "No API key configured."


def test_slow_analyzer_times_out_without_holding_the_verdict():
    slow = Hangs()
    try:
        verdict = analyze(ParsedEmail(), [slow, Fixed("ok", "DMARC_FAIL")], deadline_seconds=0.2)
    finally:
        slow.release.set()
    assert verdict.label == Label.SUSPICIOUS
    report = next(r for r in verdict.analyzers if r.analyzer == "slow")
    assert (report.status, report.detail) == (AnalyzerStatus.UNAVAILABLE, "Timed out.")


def test_email_summary():
    verdict = analyze_raw((FIXTURES / "05_attachments.eml").read_bytes())
    assert verdict.email.from_address == "ap@supplier-example.com"
    assert verdict.email.attachment_count == 2


def test_trust_signal_set_aside_by_scoring_is_shown_as_neutral():
    verdict = analyze(
        ParsedEmail(), [Fixed("auth", "DMARC_PASS"), Fixed("s", "SENDER_DOMAIN_LOOKALIKE")]
    )
    dmarc = next(s for s in verdict.signals if s.id == "DMARC_PASS")
    assert dmarc.weight == 0 and dmarc.severity == "info"
    assert "Not counted here" in dmarc.explanation
    assert verdict.score == 35


def test_counted_trust_signal_is_unchanged():
    verdict = analyze(ParsedEmail(), [Fixed("auth", "DMARC_PASS")])
    assert verdict.signals[0].weight < 0
