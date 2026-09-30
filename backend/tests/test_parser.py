import hashlib
from pathlib import Path

import pytest

from phishlens import parser
from phishlens.parser import EmailParseError, parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return parse_email((FIXTURES / name).read_bytes())


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.eml")), ids=lambda p: p.name)
def test_every_fixture_parses_as_bytes_and_as_pasted_text(path):
    raw = path.read_bytes()
    as_bytes = parse_email(raw)
    as_text = parse_email(raw.decode("utf-8"))
    assert as_bytes.from_ is not None
    assert as_text.subject == as_bytes.subject
    assert [u.href for u in as_text.urls] == [u.href for u in as_bytes.urls]


# --- Fixture-specific behavior ------------------------------------------------


def test_plain_text_headers_and_urls():
    email = load("01_plain_text.eml")
    assert email.from_.address == "billing@vendor-example.com"
    assert email.from_.display_name == "Vendor Billing"
    assert email.return_path.domain == "billing.vendor-example.com"
    assert email.message_id == "<inv-2026-09@vendor-example.com>"
    assert "dmarc=pass" in email.header_values("Authentication-Results")[0]
    # Trailing sentence punctuation and wrapping parentheses are not part of the URL.
    assert [u.href for u in email.urls] == [
        "https://portal.vendor-example.com/invoices/2026-09",
        "https://vendor-example.com/help",
        "www.vendor-example.com",
    ]
    assert all(u.source == "text" for u in email.urls)
    assert email.parse_warnings == []


def test_multipart_alternative_pairs_link_text_with_real_destination():
    email = load("02_multipart_alternative.eml")
    assert "’" in email.text_body  # quoted-printable UTF-8 decoded
    assert "<a href" in email.html_body  # base64 HTML decoded
    mismatch = email.urls[0]
    assert mismatch.visible_text == "https://outlook.office.com/mail"
    assert mismatch.href == "https://microsoft-365.login-verify.xyz/owa?u=pat"
    assert mismatch.source == "html_anchor"


def test_whitespace_hidden_inside_href_is_removed():
    email = load("02_multipart_alternative.eml")
    assert any(u.href == "https://bit.ly/3xYz" for u in email.urls)


def test_fragment_and_mailto_links_are_skipped():
    hrefs = [u.href for u in load("02_multipart_alternative.eml").urls]
    assert not any(h.startswith(("#", "mailto:")) for h in hrefs)


def test_text_part_url_already_seen_in_html_is_not_duplicated():
    hrefs = [u.href for u in load("02_multipart_alternative.eml").urls]
    assert hrefs.count("https://microsoft-365.login-verify.xyz/owa?u=pat") == 1


def test_encoded_headers_are_decoded():
    email = load("03_encoded_headers.eml")
    assert email.subject == "Dringend: Überweisung heute – vertraulich"
    assert email.from_.display_name == "Jürgen Müller (CEO)"
    assert email.reply_to[0].address == "ceo-office@protonmail.com"
    assert email.reply_to[0].display_name == "Jürgen Müller"
    assert "überweisen" in email.text_body  # latin-1 quoted-printable body


def test_html_only_email_gets_text_body_forms_and_redirects():
    email = load("04_html_only.eml")
    assert email.text_body == "DocuSign\nPlease review & sign the document."
    by_source = {u.source: u for u in email.urls}
    assert by_source["html_anchor"].visible_text == "REVIEW DOCUMENT"  # image alt text
    assert by_source["html_form"].href == "https://collect.example-bad.top/post"
    assert by_source["html_other"].href == "https://redirect.example-bad.top/go"
    # URLs inside <script> are not links the reader can click.
    assert not any("script-url" in u.href for u in email.urls)


def test_attachments_have_names_types_sizes_and_hashes():
    email = load("05_attachments.eml")
    exe, pdf = email.attachments
    assert exe.filename == "invoice.pdf.exe"
    assert exe.content_type == "application/pdf"  # declared type, kept as-is
    assert not exe.is_inline
    assert pdf.filename == "Résumé Q3.pdf"  # RFC 2231 encoded filename
    assert pdf.size == len(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")
    assert (
        pdf.sha256
        == hashlib.sha256(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n").hexdigest()
    )
    assert "attached invoice" in email.text_body


def test_inline_image_is_inline_attachment_and_html_text_reads_naturally():
    email = load("06_inline_image.eml")
    (image,) = email.attachments
    assert image.content_type == "image/png" and image.is_inline and image.filename is None
    assert email.text_body == "Read the latest post."
    assert [u.href for u in email.urls] == ["https://vendor-example.com/blog"]  # no cid:


def test_forwarded_email_is_kept_as_attachment_not_merged():
    email = load("07_forwarded_attachment.eml")
    (forwarded,) = email.attachments
    assert forwarded.content_type == "message/rfc822"
    assert forwarded.filename == "attached-message.eml"
    assert forwarded.size > 0
    assert email.urls == []  # the inner email's link is not attributed to the outer one
    assert any("attached email" in w for w in email.parse_warnings)


def test_unknown_charset_falls_back_and_warns():
    email = load("08_unknown_charset.eml")
    assert "click https://example.org/ok" in email.text_body
    assert any("x-made-up-charset" in w for w in email.parse_warnings)


def test_mbox_line_crlf_and_duplicate_from():
    email = load("09_mbox_crlf.eml")
    assert email.from_.address == "it-helpdesk@acme-defense.co"  # first From wins
    assert "\r" not in email.text_body
    assert "Email has more than one From header." in email.parse_warnings
    assert email.urls[0].href == "https://acme-defense.co/reset"


# --- Edge cases -------------------------------------------------------------------


def test_empty_input_is_rejected():
    for raw in ("", "   \n\n", b""):
        with pytest.raises(EmailParseError):
            parse_email(raw)


def test_oversized_input_is_rejected(monkeypatch):
    monkeypatch.setattr(parser, "MAX_INPUT_BYTES", 100)
    with pytest.raises(EmailParseError):
        parse_email(b"Subject: x\n\n" + b"a" * 200)


def test_body_only_paste_still_parses_with_helpful_warning():
    email = parse_email("Hi Bob,\nPlease buy gift cards today: https://gift.example.xyz/buy\n")
    assert email.from_ is None
    assert email.urls[0].href == "https://gift.example.xyz/buy"
    assert any("Show original" in w for w in email.parse_warnings)


def test_leading_whitespace_in_paste_is_ignored():
    email = parse_email("\n\n   From: a@example.com\nSubject: hi\n\nbody\n")
    assert email.from_.address == "a@example.com"
    assert email.subject == "hi"


def test_malformed_from_is_recovered():
    email = parse_email('From: "PayPal" <service@paypal.com> <attacker@evil.example>\n\nhi\n')
    assert email.from_ is not None
    assert any("From header" in w for w in email.parse_warnings)


def test_display_name_only_from_has_no_address():
    email = parse_email("From: Microsoft Support\nSubject: x\n\nhi\n")
    assert email.from_.display_name == "Microsoft Support"
    assert email.from_.address == "" and email.from_.domain == ""
    assert "From header has no email address." in email.parse_warnings


def test_empty_return_path_is_none():
    assert parse_email("Return-Path: <>\nFrom: a@b.com\n\nx\n").return_path is None


def test_html_attachment_is_not_treated_as_body():
    raw = (
        'From: a@b.com\nContent-Type: multipart/mixed; boundary="B"\n\n'
        "--B\nContent-Type: text/plain\n\nsee attached\n"
        '--B\nContent-Type: text/html\nContent-Disposition: attachment; filename="login.html"\n\n'
        '<form action="https://steal.example/x"><input type=password></form>\n'
        "--B--\n"
    )
    email = parse_email(raw)
    assert email.html_body == ""
    assert email.attachments[0].filename == "login.html"
    assert email.urls == []


def test_mime_part_limit(monkeypatch):
    monkeypatch.setattr(parser, "MAX_PARTS", 3)
    parts = "".join(f"--B\nContent-Type: text/plain\n\npart {i}\n" for i in range(10))
    email = parse_email(
        f'From: a@b.com\nContent-Type: multipart/mixed; boundary="B"\n\n{parts}--B--\n'
    )
    assert "part 1" in email.text_body and "part 5" not in email.text_body
    assert any("more than 3 parts" in w for w in email.parse_warnings)


def test_mime_depth_limit(monkeypatch):
    monkeypatch.setattr(parser, "MAX_DEPTH", 2)
    body = "Content-Type: text/plain\n\ndeep text\n"
    for i in range(5):
        body = f'Content-Type: multipart/mixed; boundary="B{i}"\n\n--B{i}\n{body}--B{i}--\n'
    email = parse_email("From: a@b.com\n" + body)
    assert "deep text" not in email.text_body
    assert any("nesting" in w for w in email.parse_warnings)


def test_url_limit(monkeypatch):
    monkeypatch.setattr(parser, "MAX_URLS", 2)
    links = " ".join(f"https://example.com/{i}" for i in range(5))
    email = parse_email(f"From: a@b.com\n\n{links}\n")
    assert len(email.urls) == 2
    assert any("first 2 of 5 links" in w for w in email.parse_warnings)


def test_duplicate_links_are_collapsed_but_different_text_is_kept():
    html = (
        '<a href="https://x.example/a">Click</a><a href="https://x.example/a">Click</a>'
        '<a href="https://x.example/a">paypal.com</a>'
    )
    email = parse_email(f"From: a@b.com\nContent-Type: text/html\n\n{html}\n")
    assert [u.visible_text for u in email.urls] == ["Click", "paypal.com"]


def test_javascript_and_data_links_are_kept_for_analysis():
    html = '<a href="javascript:alert(1)">x</a><a href="data:text/html;base64,PGh0bWw+">y</a>'
    email = parse_email(f"From: a@b.com\nContent-Type: text/html\n\n{html}\n")
    assert [u.href.split(":")[0] for u in email.urls] == ["javascript", "data"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://x.example/a).", "https://x.example/a"),
        (
            "wiki https://en.wikipedia.org/wiki/Foo_(bar) ok",
            "https://en.wikipedia.org/wiki/Foo_(bar)",
        ),
        ('"https://x.example/q?a=1"', "https://x.example/q?a=1"),
        ("<https://x.example/angle>", "https://x.example/angle"),
    ],
)
def test_text_url_boundaries(text, expected):
    assert parse_email(f"From: a@b.com\n\n{text}\n").urls[0].href == expected
