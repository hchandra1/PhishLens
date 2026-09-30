"""Links in the email body: where they claim to go versus where they really go.

Links are only inspected as text. We never visit them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from phishlens.analyzers._common import Finding, aggregate
from phishlens.domains import (
    brand_for_domain,
    find_brand_in_subdomain,
    find_lookalike,
    is_ip_address,
    organization_brand,
    registered_domain,
    split_host,
    to_unicode,
)
from phishlens.knowledge import FREE_HOSTING_DOMAINS, SUSPICIOUS_TLDS, URL_SHORTENERS, Brand
from phishlens.models import Evidence, ExtractedUrl, ParsedEmail, Signal

_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]*):", re.IGNORECASE)
_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}
_DOMAIN_IN_TEXT = re.compile(
    r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?![a-z0-9-])", re.IGNORECASE
)
# TLDs that are also common file extensions: "report.zip" in link text is a file name.
_FILE_LIKE_TLDS = {"zip", "mov"}


def parse_href(href: str) -> tuple[str, SplitResult | None]:
    """Normalize like a browser would, returning (scheme, parts)."""
    href = href.strip().replace("\\", "/")  # browsers treat backslashes as slashes
    scheme_match = _SCHEME.match(href)
    scheme = scheme_match.group(1).lower() if scheme_match else ""
    if scheme and scheme not in ("http", "https"):
        return scheme, None
    if not scheme:
        href = "http:" + href if href.startswith("//") else "http://" + href
    try:
        parts = urlsplit(href)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return scheme or "http", None
    return scheme or "http", parts


def _domain_in_link_text(text: str | None) -> str | None:
    """The web address a link's visible text shows, if it shows one."""
    if not text:
        return None
    match = _DOMAIN_IN_TEXT.search(text)
    if not match:
        return None
    host = match.group(1).lower()
    parts = split_host(host)
    if not parts.domain or not parts.suffix:
        return None
    looks_explicit = "://" in match.group(0) or host.startswith("www.")
    if parts.suffix in _FILE_LIKE_TLDS and not looks_explicit:
        return None
    return host


@dataclass(frozen=True)
class _Context:
    organization: tuple[Brand, ...]
    sender_site: str


class UrlAnalyzer:
    name = "urls"

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        context = _Context(
            organization=organization_brand([a.domain for a in email.to]),
            sender_site=registered_domain(email.from_.domain) if email.from_ else "",
        )
        findings = [f for url in email.urls for f in self._check(url, context)]
        return aggregate(self.name, findings, "links")

    def _check(self, url: ExtractedUrl, context: _Context) -> list[Finding]:
        scheme, parts = parse_href(url.href)
        link = Evidence(kind="url", label="Link", value=url.href)
        if scheme in _DANGEROUS_SCHEMES:
            return [
                Finding(
                    "URL_DANGEROUS_SCHEME",
                    f"A link runs code or opens embedded content ({scheme}:) instead of going to "
                    "a website.",
                    [link],
                )
            ]
        if parts is None or not parts.hostname:
            return []

        host = parts.hostname.rstrip(".")
        findings: list[Finding] = []
        if url.source == "html_form":
            findings.append(
                Finding(
                    "URL_FORM_ACTION",
                    f"This email contains a form asking for a password or other secret, which "
                    f"would be sent to {registered_domain(host) or host}. Real companies ask you "
                    "to sign in on their website, not inside an email.",
                    [Evidence(kind="url", label="Form sends to", value=url.href)],
                )
            )
        if parts.username is not None:
            findings.append(
                Finding(
                    "URL_USERINFO",
                    f'A link starts with "{parts.username}" to look trustworthy, but everything '
                    f"before the @ is ignored and it really goes to {host}.",
                    [link],
                )
            )
        if is_ip_address(host):
            findings.append(
                Finding(
                    "URL_IP_HOST",
                    f"A link goes to a bare internet address ({host}) instead of a named website, "
                    "which legitimate companies almost never do.",
                    [link],
                )
            )
        else:
            findings += self._domain_checks(host, link, context.organization)
        findings += self._text_mismatch(url, host, context)
        return findings

    @staticmethod
    def _domain_checks(host: str, link: Evidence, organization: tuple[Brand, ...]) -> list[Finding]:
        findings = []
        site = registered_domain(host)
        if "xn--" in host:
            findings.append(
                Finding(
                    "URL_PUNYCODE",
                    f"A link's address uses special characters: it displays as "
                    f'"{to_unicode(host)}", which can imitate a familiar site.',
                    [link, Evidence(kind="url", label="Displays as", value=to_unicode(host))],
                )
            )
        lookalike = find_lookalike(host, organization)
        if lookalike:
            findings.append(
                Finding(
                    "URL_BRAND_LOOKALIKE",
                    f"A link goes to {site}, which imitates {lookalike.brand.name}'s real site "
                    f"{lookalike.real_domain}.",
                    [link, Evidence(kind="url", label="Real site", value=lookalike.real_domain)],
                )
            )
        brand = find_brand_in_subdomain(host)
        if brand:
            findings.append(
                Finding(
                    "URL_BRAND_IN_SUBDOMAIN",
                    f'A link puts "{brand.name}" at the start of its address, but the site it '
                    f"really goes to is {site}.",
                    [link, Evidence(kind="url", label="Actually goes to", value=site)],
                )
            )
        if site in URL_SHORTENERS or host in URL_SHORTENERS:
            findings.append(
                Finding(
                    "URL_SHORTENER",
                    f"A link uses a shortening service ({site}), which hides where it really goes.",
                    [link],
                )
            )
        hosting = next(
            (d for d in FREE_HOSTING_DOMAINS if host == d or host.endswith("." + d)), None
        )
        if hosting is None and "ipfs" in host:
            hosting = "an IPFS gateway"  # IPFS content is served from many look-alike gateways
        if hosting:
            findings.append(
                Finding(
                    "URL_FREE_HOSTING",
                    f"A link goes to a page on {hosting}, a free hosting service anyone can "
                    "publish to. Fake sign-in pages are often hosted this way.",
                    [link],
                )
            )
        tld = split_host(host).suffix.rpartition(".")[2]
        if tld in SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    "URL_SUSPICIOUS_TLD",
                    f"A link goes to a site ending in .{tld}, an address ending that is "
                    "frequently used by scam sites.",
                    [link],
                )
            )
        return findings

    @staticmethod
    def _text_mismatch(url: ExtractedUrl, host: str, context: _Context) -> list[Finding]:
        shown = _domain_in_link_text(url.visible_text)
        if not shown:
            return []
        shown_site, real_site = registered_domain(shown), registered_domain(host)
        if shown_site == real_site:
            return []
        shown_brand = brand_for_domain(shown_site, include_mailbox_domains=True)
        if shown_brand and shown_brand is brand_for_domain(real_site, include_mailbox_domains=True):
            return []  # e.g. text says outlook.com, link goes to office.com
        own_org = any(shown_site in b.domains for b in context.organization)
        if real_site == context.sender_site and not shown_brand and not own_org:
            # Newsletters send links through their own click tracker. Still flagged when the
            # text shows a well-known brand or the recipient's own organization.
            return []
        return [
            Finding(
                "LINK_TEXT_MISMATCH",
                f"A link says it goes to {shown_site}, but it actually goes to {real_site}.",
                [
                    Evidence(kind="url", label="Link text", value=url.visible_text or shown),
                    Evidence(kind="url", label="Actually goes to", value=url.href),
                ],
            )
        ]
