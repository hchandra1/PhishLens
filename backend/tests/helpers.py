from phishlens.models import Attachment, EmailAddress, ExtractedUrl, Header, ParsedEmail, Signal


def make_email(
    *,
    sender: str | None = "Vendor <billing@vendor-example.com>",
    to: str = "pat@acme-defense.com",
    reply_to: str | None = None,
    return_path: str | None = None,
    auth: str | list[str] | None = None,
    urls: list[tuple[str, str | None] | tuple[str, str | None, str]] = (),
    attachments: list[tuple[str, str]] = (),
) -> ParsedEmail:
    """Build a ParsedEmail directly, so analyzer tests don't depend on the parser."""
    headers = []
    for value in [auth] if isinstance(auth, str) else auth or []:
        headers.append(Header(name="Authentication-Results", value=value))
    if sender:
        headers.append(Header(name="From", value=sender))
    return ParsedEmail(
        headers=headers,
        from_=_address(sender) if sender else None,
        to=[_address(to)],
        reply_to=[_address(reply_to)] if reply_to else [],
        return_path=_address(return_path) if return_path else None,
        urls=[
            ExtractedUrl(href=u[0], visible_text=u[1], source=u[2] if len(u) > 2 else "html_anchor")
            for u in urls
        ],
        attachments=[
            Attachment(filename=name, content_type=ctype, size=10, sha256="0" * 64)
            for name, ctype in attachments
        ],
    )


def _address(value: str) -> EmailAddress:
    if "<" in value:
        name, _, addr = value.partition("<")
        return EmailAddress(display_name=name.strip().strip('"'), address=addr.rstrip(">"))
    return EmailAddress(address=value)


def ids(signals: list[Signal]) -> list[str]:
    return [s.id for s in signals]
