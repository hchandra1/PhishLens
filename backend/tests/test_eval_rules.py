"""Rules added after studying the dev split of the evaluation corpus (see eval/)."""

import pytest
from helpers import ids, make_email

from phishlens.analyzers.content import ContentAnalyzer, find_disguised_words
from phishlens.analyzers.sender import SenderAnalyzer, brand_in_display_name
from phishlens.analyzers.urls import UrlAnalyzer
from phishlens.parser import parse_email

# --- Forms: only ones asking for secrets count ------------------------------------------


@pytest.mark.parametrize(
    ("form", "source"),
    [
        (
            '<form action="https://x.example/s"><input name="q"><input type="submit"></form>',
            "html_other",
        ),  # noqa: E501
        ('<form action="https://x.example/sub"><input name="email"></form>', "html_other"),
        ('<form action="https://x.example/p"><input type="password" name="p"></form>', "html_form"),
        ('<form action="https://x.example/p"><input name="card_number"></form>', "html_form"),
        (
            '<form action="https://x.example/p"><input placeholder="One-time PIN"></form>',
            "html_form",
        ),
    ],
)
def test_form_classification(form, source):
    email = parse_email(f"From: a@b.com\nContent-Type: text/html\n\n{form}\n")
    assert email.urls[0].source == source


# --- Link text vs the sender's own click tracker ------------------------------------------


def test_link_through_senders_own_tracker_is_not_a_mismatch():
    email = make_email(
        sender="News <news@newsletter.online-example.com>",
        urls=[("https://click.online-example.com/r?id=1", "www.shopper-example.com")],
    )
    assert "LINK_TEXT_MISMATCH" not in ids(UrlAnalyzer().analyze(email))


@pytest.mark.parametrize("shown", ["www.paypal.com", "acme-defense.com/login"])
def test_senders_own_domain_still_flagged_when_text_shows_a_brand_or_your_org(shown):
    # An attacker linking to their own domain while showing a trusted name.
    email = make_email(
        sender="X <x@evil-example.com>", urls=[("https://evil-example.com/a", shown)]
    )
    assert "LINK_TEXT_MISMATCH" in ids(UrlAnalyzer().analyze(email))


# --- Display names claiming to be your organization or its IT ---------------------------


@pytest.mark.parametrize(
    "name", ["acme-defense.com Support", "FAX acme-defense.com", "Acme Defense HR/Executive"]
)
def test_display_name_uses_your_organization(name):
    email = make_email(sender=f'"{name}" <x@ecomavvy-example.com>')
    assert ids(SenderAnalyzer().analyze(email)) == ["DISPLAY_NAME_ORG_MISMATCH"]


@pytest.mark.parametrize("name", ["EMAIL SERVER", "Admin IT HelpDesk", "Webmail Administrator"])
def test_display_name_claims_to_run_your_email(name):
    email = make_email(sender=f'"{name}" <x@cubepeople-example.com>')
    assert ids(SenderAnalyzer().analyze(email)) == ["DISPLAY_NAME_ROLE_EXTERNAL"]


@pytest.mark.parametrize(
    "sender",
    [
        '"Acme Defense IT Helpdesk" <helpdesk@acme-defense.com>',  # really internal
        '"Pat Lee (Acme Defense) via DocuSign" <dse@docusign.net>',  # real platform relaying
        '"Vendor Billing" <billing@vendor-example.com>',
    ],
)
def test_organization_claims_do_not_fire_on_legitimate_senders(sender):
    assert ids(SenderAnalyzer().analyze(make_email(sender=sender))) == []


def test_dotted_brand_acronyms():
    assert brand_in_display_name("D.H.L (Express)").name == "DHL"
    assert brand_in_display_name("J.D. Smith") is None


# --- Free hosting ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "href",
    [
        "https://ipfs.io/ipfs/bafy/login.html",
        "https://pub-57c5b2156bab.r2.dev/index.html",
        "https://xwebmail-bautho-xi.vercel.app/",
        "https://firebasestorage.googleapis.com/v0/b/x/o/a.html",
        "https://l4a2ap5-ipfs-dweb-link.translate.goog/x",
        "https://bafy.ipfs.nftstorage.link/",
    ],
)
def test_free_hosting(href):
    assert "URL_FREE_HOSTING" in ids(UrlAnalyzer().analyze(make_email(urls=[(href, "Verify")])))


def test_ordinary_sites_are_not_free_hosting():
    email = make_email(
        urls=[("https://www.vendor-example.com/", "Home"), ("https://github.com/x", None)]
    )
    assert "URL_FREE_HOSTING" not in ids(UrlAnalyzer().analyze(email))


# --- Content --------------------------------------------------------------------------------


def test_recipient_address_in_subject():
    email = make_email().model_copy(
        update={"subject": "Final notice: PAT@acme-defense.com suspended"}
    )
    assert ids(ContentAnalyzer().analyze(email)) == ["SUBJECT_MENTIONS_RECIPIENT"]
    assert ContentAnalyzer().analyze(make_email().model_copy(update={"subject": "Hi Pat"})) == []


@pytest.mark.parametrize(
    "text",
    [
        "Kе﻿﻿еp My Password",  # Cyrillic е plus zero-width no-break spaces
        "Verify your аccount",  # Cyrillic а in a Latin word
        "Pass​word expires",
        "C​h​a​r​l​es",
    ],
)
def test_disguised_words(text):
    assert find_disguised_words(text)


@pytest.mark.parametrize(
    "text",
    [
        "Use a 10μF capacitor and 5μm tolerance.",  # Greek letters in engineering units
        "Здравствуйте, Pat. Спасибо!",  # separate Russian and English words
        "می‌خواهم",  # Persian zero-width non-joiner is part of the word
        "Big sale inside ‌ ‌ ‌ ‌",  # newsletter preheader padding
    ],
)
def test_ordinary_text_is_not_disguised(text):
    assert find_disguised_words(text) == []


def test_disguised_display_name_is_caught():
    email = make_email(sender='"C​h​a​rles" <x@example-sender.com>')
    assert "TEXT_OBFUSCATION" in ids(ContentAnalyzer().analyze(email))
