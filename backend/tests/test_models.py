import pytest
from pydantic import ValidationError

from phishlens.models import (
    Attachment,
    EmailAddress,
    EmailSummary,
    Evidence,
    Header,
    Label,
    ParsedEmail,
    Severity,
    Signal,
    Verdict,
)


def make_signal(**overrides) -> Signal:
    fields = dict(
        analyzer="auth",
        id="SPF_FAIL",
        severity=Severity.HIGH,
        weight=30,
        evidence=[Evidence(kind="header", label="Authentication-Results", value="spf=fail")],
        explanation="The sending server was not authorized to send mail for this domain.",
    )
    return Signal(**(fields | overrides))


def test_email_address_domain_is_lowercased():
    assert EmailAddress(address="Alice@Example.COM.").domain == "example.com"
    assert EmailAddress(address="no-at-sign").domain == ""


def test_header_values_case_insensitive_and_keeps_duplicates():
    email = ParsedEmail(
        headers=[
            Header(name="Received", value="hop 1"),
            Header(name="Subject", value="hi"),
            Header(name="received", value="hop 2"),
        ]
    )
    assert email.header_values("RECEIVED") == ["hop 1", "hop 2"]


def test_parsed_email_json_round_trip_uses_from_key():
    email = ParsedEmail(from_=EmailAddress(display_name="Microsoft 365", address="x@gmail.com"))
    dumped = email.model_dump_json()
    assert '"from":' in dumped
    assert ParsedEmail.model_validate_json(dumped) == email


@pytest.mark.parametrize("bad_id", ["spf_fail", "SPF-FAIL", "", "1SPF"])
def test_signal_id_must_be_upper_snake(bad_id):
    with pytest.raises(ValidationError):
        make_signal(id=bad_id)


def test_signal_weight_is_bounded():
    with pytest.raises(ValidationError):
        make_signal(weight=1000)
    assert make_signal(weight=-20).weight == -20  # trust signals are allowed


def test_signal_requires_explanation():
    with pytest.raises(ValidationError):
        make_signal(explanation="")


def test_contracts_reject_unknown_fields():
    with pytest.raises(ValidationError):
        make_signal(confidence=0.9)


def test_attachment_hash_must_be_sha256_hex():
    with pytest.raises(ValidationError):
        Attachment(filename="a.pdf", content_type="application/pdf", size=1, sha256="abc")


def test_severity_ordering():
    ordered = sorted(Severity, key=lambda s: s.rank, reverse=True)
    assert ordered == [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def test_verdict_json_round_trip():
    verdict = Verdict(
        label=Label.PHISHING,
        score=87.5,
        signals=[make_signal()],
        summary="This email failed sender checks.",
        recommended_actions=["Do not click any links."],
        email=EmailSummary(
            subject="Urgent",
            from_display="IT",
            from_address="it@evil.xyz",
            url_count=1,
            attachment_count=0,
        ),
    )
    restored = Verdict.model_validate_json(verdict.model_dump_json())
    assert restored == verdict


def test_verdict_score_is_bounded():
    with pytest.raises(ValidationError):
        Verdict(
            label=Label.SAFE,
            score=-5,
            signals=[],
            summary="",
            recommended_actions=[],
            email=EmailSummary(
                subject="", from_display="", from_address="", url_count=0, attachment_count=0
            ),
        )
