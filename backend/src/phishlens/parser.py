"""Turn raw email source (.eml bytes or pasted "show original" text) into a ParsedEmail.

The parser is deliberately forgiving. Phishing mail is often malformed on
purpose, so instead of rejecting odd input we recover what we can and record
what was wrong in ParsedEmail.parse_warnings.

Nothing here touches the network, writes to disk, or executes content.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from email.utils import getaddresses, parseaddr

from bs4 import BeautifulSoup

from phishlens.models import Attachment, EmailAddress, ExtractedUrl, Header, ParsedEmail

# Limits against oversized or deliberately pathological input (MIME bombs).
MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_PARTS = 250
MAX_DEPTH = 10
MAX_URLS = 500
MAX_LINK_TEXT = 500

_POLICY = policy.default

# Mailbox exports (Thunderbird, mbox) start with a "From sender date" line that isn't a header.
_MBOX_FROM_LINE = re.compile(rb"^From [^\r\n]*\r?\n")
_MBOX_FROM_LINE_TEXT = re.compile(r"^From [^\r\n]*\r?\n")
_TEXT_URL = re.compile(r"""(?:https?://|www\.)[^\s<>"'`]+""", re.IGNORECASE)
_URL_CONTROL_CHARS = re.compile(r"[\t\r\n]")
_SKIPPED_SCHEMES = ("mailto:", "tel:", "sms:", "cid:")
_SECRET_FIELD = re.compile(
    r"pass|pwd|\bpin\b|cvv|cvc|card.?(?:num|no)|\bssn\b|one-time-code|\botp\b", re.IGNORECASE
)
_BLOCK_TAGS = ["p", "div", "li", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"]
_META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)


class EmailParseError(ValueError):
    """The input can't be treated as an email at all (empty or too large)."""


@dataclass
class _WalkState:
    text_parts: list[str] = field(default_factory=list)
    html_parts: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    part_count: int = 0


def parse_email(raw: bytes | str) -> ParsedEmail:
    msg = _load(raw)
    state = _WalkState()

    headers = [
        Header(name=name, value=_header_text(name, value)) for name, value in msg.raw_items()
    ]
    if not headers:
        state.warnings.append(
            "No email headers found. Paste the full original message source "
            '("Show original" / "View source"), not just the body.'
        )
    if len(_raw_values(msg, "From")) > 1:
        state.warnings.append("Email has more than one From header.")

    from_addresses = _addresses(msg, "From", state.warnings)
    _walk(msg, 0, state)
    _collect_defects(msg, state.warnings)

    text_body = "\n".join(state.text_parts)
    html_body = "\n".join(state.html_parts)
    urls: list[ExtractedUrl] = []
    if html_body:
        html_urls, html_text = _parse_html(html_body)
        urls.extend(html_urls)
        if not text_body:
            text_body = html_text
    urls.extend(_text_urls("\n".join(state.text_parts), seen={u.href for u in urls}))
    urls = _dedupe(urls)
    if len(urls) > MAX_URLS:
        state.warnings.append(f"Only the first {MAX_URLS} of {len(urls)} links were analyzed.")
        urls = urls[:MAX_URLS]

    return ParsedEmail(
        headers=headers,
        message_id=_first_header(msg, "Message-ID"),
        subject=_first_header(msg, "Subject") or "",
        date=_first_header(msg, "Date"),
        from_=from_addresses[0] if from_addresses else None,
        reply_to=_addresses(msg, "Reply-To", state.warnings),
        return_path=_return_path(msg),
        to=_addresses(msg, "To", state.warnings),
        text_body=text_body,
        html_body=html_body,
        urls=urls,
        attachments=state.attachments,
        parse_warnings=list(dict.fromkeys(state.warnings)),
    )


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def _load(raw: bytes | str) -> EmailMessage:
    size = len(raw) if isinstance(raw, bytes) else len(raw.encode("utf-8", "replace"))
    if size > MAX_INPUT_BYTES:
        raise EmailParseError(f"Email is larger than {MAX_INPUT_BYTES // (1024 * 1024)} MB.")

    if isinstance(raw, str):
        # Pasted source is already text and may contain non-ASCII characters.
        text = _MBOX_FROM_LINE_TEXT.sub("", raw.lstrip(), count=1)
        if not text.strip():
            raise EmailParseError("Email is empty.")
        return Parser(policy=_POLICY).parsestr(text)  # type: ignore[return-value]

    data = _MBOX_FROM_LINE.sub(b"", raw.lstrip(), count=1)
    if not data.strip():
        raise EmailParseError("Email is empty.")
    return BytesParser(policy=_POLICY).parsebytes(data)  # type: ignore[return-value]


# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", value).strip()


def _header_text(name: str, raw: str) -> str:
    """Decoded header value, falling back step by step for malformed headers."""
    try:
        return str(_POLICY.header_fetch_parse(name, raw)).strip()
    except Exception:
        pass
    try:
        return str(make_header(decode_header(_unfold(raw))))
    except Exception:
        return _unfold(raw)


def _raw_values(msg: EmailMessage, name: str) -> list[str]:
    lname = name.lower()
    return [value for key, value in msg.raw_items() if key.lower() == lname]


def _first_header(msg: EmailMessage, name: str) -> str | None:
    values = _raw_values(msg, name)
    return _header_text(name, values[0]) if values else None


def _addresses(msg: EmailMessage, name: str, warnings: list[str]) -> list[EmailAddress]:
    result: list[EmailAddress] = []
    for raw in _raw_values(msg, name):
        try:
            header = _POLICY.header_fetch_parse(name, raw)
            pairs = [(a.display_name, a.addr_spec) for a in header.addresses]
            if header.defects:
                warnings.append(f"{name} header is malformed.")
        except Exception:
            warnings.append(f"{name} header is malformed.")
            pairs = [(_decode_words(d), a) for d, a in getaddresses([_unfold(raw)])]
        for display_name, addr_spec in pairs:
            if "@" not in addr_spec:
                # e.g. `From: Microsoft Support`. Keep the name, since it may be impersonation.
                warnings.append(f"{name} header has no email address.")
                display_name = display_name or addr_spec.strip('"<> ')
                if not display_name:
                    continue
                addr_spec = ""
            result.append(EmailAddress(display_name=display_name or "", address=addr_spec))
    return result


def _decode_words(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _return_path(msg: EmailMessage) -> EmailAddress | None:
    values = _raw_values(msg, "Return-Path")
    if not values:
        return None
    _, addr = parseaddr(_unfold(values[0]))
    return EmailAddress(address=addr) if addr else None


# --------------------------------------------------------------------------
# MIME tree
# --------------------------------------------------------------------------


def _walk(part: EmailMessage, depth: int, state: _WalkState) -> None:
    if state.part_count >= MAX_PARTS:
        state.warnings.append(f"Email has more than {MAX_PARTS} parts; the rest were skipped.")
        return
    state.part_count += 1
    ctype = part.get_content_type()

    if ctype == "message/rfc822":
        # A forwarded email. Keep it as an attachment rather than mixing its
        # links and text into this one; it can be analyzed on its own.
        state.warnings.append("Email contains an attached email. Analyze that one separately.")
        _add_attachment(part, state, default_name="attached-message.eml")
        return

    if part.is_multipart():
        if depth >= MAX_DEPTH:
            state.warnings.append(f"MIME nesting deeper than {MAX_DEPTH} levels was skipped.")
            return
        for sub in part.iter_parts():
            _walk(sub, depth + 1, state)  # type: ignore[arg-type]
        return

    disposition = part.get_content_disposition()
    filename = _filename(part)
    if disposition == "attachment" or filename:
        _add_attachment(part, state)
    elif ctype == "text/plain":
        state.text_parts.append(_decode_text(part, state.warnings))
    elif ctype == "text/html":
        state.html_parts.append(_decode_text(part, state.warnings))
    else:
        _add_attachment(part, state)


def _filename(part: EmailMessage) -> str | None:
    try:
        return part.get_filename()
    except Exception:
        return None


def _decode_text(part: EmailMessage, warnings: list[str]) -> str:
    try:
        text = part.get_content()
    except Exception:
        charset = part.get_content_charset() or "unknown"
        warnings.append(f"Text part uses an unreadable character set ({charset}).")
        payload = part.get_payload(decode=True) or b""
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(payload)
    return text.replace("\r\n", "\n")


def _add_attachment(part: EmailMessage, state: _WalkState, default_name: str | None = None) -> None:
    payload = _payload_bytes(part)
    state.attachments.append(
        Attachment(
            filename=_filename(part) or default_name,
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            is_inline=part.get_content_disposition() != "attachment",
        )
    )


def _payload_bytes(part: EmailMessage) -> bytes:
    if part.is_multipart():  # message/rfc822: hash the embedded message as sent
        try:
            return part.get_payload(0).as_bytes()  # type: ignore[union-attr]
        except Exception:
            return b""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def _collect_defects(msg: EmailMessage, warnings: list[str]) -> None:
    for part in msg.walk():
        for defect in part.defects:
            warnings.append(f"MIME defect: {type(defect).__name__}")


# --------------------------------------------------------------------------
# Links
# --------------------------------------------------------------------------


def _parse_html(html: str) -> tuple[list[ExtractedUrl], str]:
    """Extract links (with the text the reader sees) and a plain-text rendering."""
    soup = BeautifulSoup(html, "html.parser")
    urls: list[ExtractedUrl] = []

    for tag in soup.find_all(["a", "area", "form", "iframe", "meta"]):
        match tag.name:
            case "a" | "area":
                href, source = tag.get("href"), "html_anchor"
                text = _visible_text(tag)
            case "form":
                # Search and newsletter-signup boxes are harmless; a form asking for a
                # password, PIN or card number inside an email is not.
                source = "html_form" if _asks_for_secrets(tag) else "html_other"
                href, text = tag.get("action"), None
            case "iframe":
                href, source, text = tag.get("src"), "html_other", None
            case _:  # meta refresh redirects
                if str(tag.get("http-equiv", "")).lower() != "refresh":
                    continue
                found = _META_REFRESH_URL.search(str(tag.get("content", "")))
                href, source, text = (found.group(1) if found else None), "html_other", None
        cleaned = _clean_href(href)
        if cleaned:
            urls.append(ExtractedUrl(href=cleaned, visible_text=text, source=source))

    return urls, _html_to_text(soup)


def _html_to_text(soup: BeautifulSoup) -> str:
    """Readable text: line breaks only at block elements, not at every inline tag."""
    for tag in soup(["script", "style", "head", "title"]):
        tag.decompose()
    for tag in soup.find_all(_BLOCK_TAGS):
        tag.insert_after("\n")
    for br in soup.find_all("br"):
        br.replace_with("\n")
    lines = (" ".join(line.split()) for line in soup.get_text().splitlines())
    return "\n".join(line for line in lines if line)


def _asks_for_secrets(form) -> bool:
    for field_ in form.find_all("input"):
        if str(field_.get("type", "")).lower() == "password":
            return True
        hints = " ".join(
            str(field_.get(a, "")) for a in ("name", "id", "placeholder", "autocomplete")
        )
        if _SECRET_FIELD.search(hints):
            return True
    return False


def _visible_text(tag) -> str | None:
    text = " ".join(tag.get_text(" ").split())
    if not text:
        img = tag.find("img") if tag.name == "a" else tag
        alt = img.get("alt") if img is not None else None
        text = " ".join(str(alt).split()) if alt else ""
    return text[:MAX_LINK_TEXT] or None


def _clean_href(href: object) -> str | None:
    if not isinstance(href, str):
        return None
    # Browsers ignore tabs and newlines inside URLs, and attackers use them to hide links.
    cleaned = _URL_CONTROL_CHARS.sub("", href).strip()
    if not cleaned or cleaned.startswith("#") or cleaned.lower().startswith(_SKIPPED_SCHEMES):
        return None
    return cleaned


def _text_urls(text: str, seen: set[str]) -> list[ExtractedUrl]:
    urls = []
    for match in _TEXT_URL.finditer(text):
        href = _trim_url(match.group(0))
        if href not in seen:
            urls.append(ExtractedUrl(href=href, visible_text=None, source="text"))
    return urls


def _trim_url(url: str) -> str:
    """Drop sentence punctuation that the regex swallowed, e.g. 'see https://x.com/a).'"""
    url = url.rstrip(".,;:!?'\"")
    for opener, closer in (("(", ")"), ("[", "]")):
        while url.endswith(closer) and url.count(closer) > url.count(opener):
            url = url[:-1].rstrip(".,;:!?'\"")
    return url


def _dedupe(urls: list[ExtractedUrl]) -> list[ExtractedUrl]:
    return list({(u.href, u.visible_text, u.source): u for u in urls}.values())
