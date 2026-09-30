from helpers import ids, make_email

from phishlens.analyzers.sender import SenderAnalyzer, brand_in_display_name
from phishlens.models import Header

analyze = SenderAnalyzer().analyze


def test_ordinary_vendor_email_is_clean():
    assert analyze(make_email()) == []


def test_real_brand_sending_under_its_own_name_is_clean():
    assert (
        analyze(
            make_email(
                sender="Microsoft <account-security-noreply@accountprotection.microsoft.com>"
            )
        )
        == []
    )  # noqa: E501
    assert analyze(make_email(sender="Pat Lee via DocuSign <dse_na2@docusign.net>")) == []


def test_brand_display_name_from_other_domain():
    signals = analyze(make_email(sender='"Microsoft 365" <alerts@notices-portal.net>'))
    assert ids(signals) == ["DISPLAY_NAME_BRAND_MISMATCH"]
    assert "notices-portal.net" in signals[0].explanation


def test_brand_display_name_from_freemail_even_if_brand_owns_the_mailbox_service():
    assert ids(analyze(make_email(sender="Microsoft Account Team <helpdesk@outlook.com>"))) == [
        "DISPLAY_NAME_BRAND_MISMATCH"
    ]


def test_display_name_brand_match_resists_lookalike_characters():
    assert brand_in_display_name("Micr0soft Security").name == "Microsoft"
    assert brand_in_display_name("Market Outlook Weekly") is None
    assert brand_in_display_name("Start-Ups Digest") is None


def test_display_name_containing_a_different_address():
    signals = analyze(make_email(sender='"service@paypal.com" <x@mailer-host.biz>'))
    assert "DISPLAY_NAME_EMAIL_MISMATCH" in ids(signals)


def test_role_name_from_freemail():
    assert ids(analyze(make_email(sender="IT Helpdesk <acme.it.help@gmail.com>"))) == [
        "DISPLAY_NAME_ROLE_FREEMAIL"
    ]
    assert ids(analyze(make_email(sender="Jürgen Müller (CEO) <jm.ceo@gmail.com>"))) == [
        "DISPLAY_NAME_ROLE_FREEMAIL"
    ]
    # A role name at a company domain, or a normal person at gmail, is fine.
    assert analyze(make_email(sender="IT Helpdesk <it@acme-defense.com>")) == []
    assert analyze(make_email(sender="Pat's Friend <friend@gmail.com>")) == []


def test_sender_domain_lookalike_of_brand_and_of_own_organization():
    brand = analyze(make_email(sender="PayPal <service@paypa1.com>"))
    assert "SENDER_DOMAIN_LOOKALIKE" in ids(brand)
    org = analyze(make_email(sender="Payroll <payroll@acme-defense.co>"))
    assert ids(org) == ["SENDER_DOMAIN_LOOKALIKE"]
    assert "your organization" in org[0].explanation


def test_reply_to():
    assert ids(analyze(make_email(reply_to="ceo.office@protonmail.com"))) == ["REPLY_TO_FREEMAIL"]
    assert ids(analyze(make_email(reply_to="ar@other-company.com"))) == ["REPLY_TO_MISMATCH"]
    assert analyze(make_email(reply_to="support@help.vendor-example.com")) == []


def test_return_path_mismatch_is_informational_only():
    (signal,) = analyze(make_email(return_path="bounce-123@sendgrid.net"))
    assert signal.id == "RETURN_PATH_MISMATCH"
    assert signal.severity == "info"
    assert analyze(make_email(return_path="bounces@mail.vendor-example.com")) == []


def test_missing_sender_address():
    assert ids(analyze(make_email(sender=None))) == ["FROM_MISSING"]
    signals = analyze(
        make_email(sender="Microsoft Support <>").model_copy(
            update={
                "from_": make_email().from_.model_copy(
                    update={"address": "", "display_name": "Microsoft Support"}
                )
            }  # noqa: E501
        )
    )
    assert set(ids(signals)) == {"FROM_MISSING", "DISPLAY_NAME_BRAND_MISMATCH"}


def test_duplicate_from_headers():
    email = make_email()
    email = email.model_copy(
        update={"headers": [*email.headers, Header(name="From", value="ceo@acme-defense.com")]}
    )
    assert ids(analyze(email)) == ["FROM_DUPLICATE"]
