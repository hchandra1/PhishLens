import pytest
from helpers import ids, make_email

from phishlens.analyzers.urls import UrlAnalyzer

analyze = UrlAnalyzer().analyze


def check(*urls):
    return ids(analyze(make_email(urls=list(urls))))


def test_ordinary_links_are_clean():
    assert (
        check(
            ("https://vendor-example.com/invoice", "View invoice"),
            ("https://www.vendor-example.com", "www.vendor-example.com"),
            (
                "https://click.vendor-example.com/t?u=1",
                "vendor-example.com",
            ),  # same registered domain
            ("https://lh3.googleusercontent.com/a.png", None, "html_other"),
            ("https://acme-defense.sharepoint.com/sites/x", "Open in SharePoint"),
        )
        == []
    )


@pytest.mark.parametrize(
    ("text", "href"),
    [
        ("https://outlook.office.com/mail", "https://microsoft-365.login-verify.xyz/owa"),
        ("paypal.com", "https://secure-account.example.net/"),
        ("Go to www.chase.com now", "http://203.0.113.9/login"),
    ],
)
def test_link_text_mismatch(text, href):
    signals = analyze(make_email(urls=[(href, text)]))
    mismatch = next(s for s in signals if s.id == "LINK_TEXT_MISMATCH")
    assert [e.label for e in mismatch.evidence] == ["Link text", "Actually goes to"]
    assert mismatch.evidence[1].value == href


def test_link_text_that_is_not_an_address_is_not_a_mismatch():
    assert check(("https://files.vendor-example.com/r", "Download report.zip")) == []
    assert check(("https://vendor-example.com/x", "Contract_v2.pdf")) == []


def test_link_text_and_destination_owned_by_the_same_brand():
    assert check(("https://login.microsoftonline.com/", "outlook.com")) == []


@pytest.mark.parametrize(
    ("href", "expected"),
    [
        ("http://192.0.2.44/login", "URL_IP_HOST"),
        ("http://3232235777/", "URL_IP_HOST"),
        ("https://paypal.com@198.51.100.7/", "URL_USERINFO"),
        ("https://www.paypa1.com/signin", "URL_BRAND_LOOKALIKE"),
        ("https://microsoft.login-secure.example/", "URL_BRAND_IN_SUBDOMAIN"),
        ("https://xn--pypal-4ve.com/", "URL_PUNYCODE"),
        ("https://bit.ly/3xYz", "URL_SHORTENER"),
        ("https://invoice-view.top/a", "URL_SUSPICIOUS_TLD"),
        ("javascript:fetch('//evil')", "URL_DANGEROUS_SCHEME"),
        ("data:text/html;base64,PGgxPg==", "URL_DANGEROUS_SCHEME"),
        ("https:\\\\paypal-verify.com\\x", "URL_BRAND_LOOKALIKE"),  # backslashes act as slashes
        ("www.acme-defense.co/reset", "URL_BRAND_LOOKALIKE"),  # imitates recipient's org
    ],
)
def test_url_checks(href, expected):
    assert expected in check((href, None))


def test_form_action():
    assert check(("https://collect.example.net/post", None, "html_form")) == ["URL_FORM_ACTION"]


def test_repeated_problem_is_one_signal_with_capped_evidence():
    urls = [(f"https://bit.ly/{i}", None) for i in range(10)]
    (signal,) = analyze(make_email(urls=urls))
    assert signal.id == "URL_SHORTENER"
    assert len(signal.evidence) == 3
    assert "9 other links have the same problem" in signal.explanation


def test_malformed_urls_do_not_crash():
    assert check(("http://[::1", None), ("http://host:99999/", None), ("", None)) == []
