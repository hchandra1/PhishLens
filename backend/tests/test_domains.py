import pytest

from phishlens.domains import (
    find_brand_in_subdomain,
    find_lookalike,
    is_ip_address,
    organization_brand,
    registered_domain,
    skeleton,
)


@pytest.mark.parametrize(
    ("host", "registered"),
    [
        ("microsoft.login-secure.xyz", "login-secure.xyz"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("attacker.github.io", "attacker.github.io"),  # shared hosting tenants are separate
        ("Mail.Google.COM.", "google.com"),
    ],
)
def test_registered_domain(host, registered):
    assert registered_domain(host) == registered


def test_skeleton_collapses_lookalike_characters():
    assert skeleton("pаypa1") == "paypal"  # Cyrillic а, digit 1
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("Pâypal") == "paypal"


@pytest.mark.parametrize(
    ("host", "brand", "technique"),
    [
        ("paypa1.com", "PayPal", "homoglyph"),
        ("pаypal.com", "PayPal", "homoglyph"),
        ("xn--pypal-4ve.com", "PayPal", "homoglyph"),
        ("rnicrosoft.com", "Microsoft", "homoglyph"),
        ("gooogle.com", "Google", "typo"),
        ("linkedln.com", "LinkedIn", "typo"),
        ("micrsooft.net", "Microsoft", "typo"),
        ("paypal-secure.com", "PayPal", "combo"),
        ("microsoftsupport.net", "Microsoft", "combo"),
        ("sam-gov-renewal.com", "SAM.gov", "combo"),
        ("dhl-tracking.info", "DHL", "combo"),
        ("paypal.xyz", "PayPal", "tld_swap"),
    ],
)
def test_lookalikes_are_detected(host, brand, technique):
    match = find_lookalike(host)
    assert match is not None
    assert (match.brand.name, match.technique) == (brand, technique)


@pytest.mark.parametrize(
    "host",
    [
        # Real brand domains and mailbox providers.
        "paypal.com", "mail.google.com", "gmail.com", "outlook.com", "docusign.net",
        # Ordinary domains close to short brand names or containing them as substrings.
        "apply.com", "adore.com", "sign-ups.com", "purchase-order.com", "office-depot.com",
        "googleusercontent.com", "amazonses.com", "acme-defense.com", "192.168.1.1",
    ],
)  # fmt: skip
def test_legitimate_domains_are_not_lookalikes(host):
    assert find_lookalike(host) is None


@pytest.mark.parametrize(
    ("host", "brand"),
    [
        ("microsoft.login-secure.xyz", "Microsoft"),
        ("paypal.com.evil.ru", "PayPal"),
        ("ups.track-parcel.com", "UPS"),
        ("www.sam-gov.renew-now.top", "SAM.gov"),
        ("outlook.live.com", None),  # Microsoft's own consumer mail
        ("contoso.sharepoint.com", None),
        ("login.microsoftonline.com", None),
        ("sign-ups.example.com", None),
        ("www.vendor-example.com", None),
    ],
)
def test_brand_in_subdomain(host, brand):
    found = find_brand_in_subdomain(host)
    assert (found.name if found else None) == brand


def test_recipient_organization_lookalike():
    org = organization_brand(["acme-defense.com", "gmail.com"])
    assert org[0].domains == {"acme-defense.com"}  # free mailbox recipients ignored
    assert find_lookalike("acme-defense.co", org).technique == "tld_swap"
    assert find_lookalike("acrne-defense.com", org).technique == "homoglyph"
    assert find_lookalike("acme-defense-hr.com", org).technique == "combo"
    assert find_lookalike("mail.acme-defense.com", org) is None
    assert organization_brand(["gmail.com"]) == ()


@pytest.mark.parametrize(
    ("host", "expected"),
    [("10.0.0.1", True), ("[::1]", True), ("3232235777", True), ("0xC0A80001", True),
     ("example.com", False), ("1password.com", False)],
)  # fmt: skip
def test_is_ip_address(host, expected):
    assert is_ip_address(host) is expected
