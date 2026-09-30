"""Who the email claims to be from, versus where it actually came from."""

from __future__ import annotations

import re

from phishlens.analyzers._common import Finding, aggregate
from phishlens.domains import (
    brand_for_domain,
    find_lookalike,
    organization_brand,
    registered_domain,
    skeleton,
)
from phishlens.knowledge import (
    BRANDS,
    FREEMAIL_DOMAINS,
    MAILBOX_ROLE_NAMES,
    ROLE_DISPLAY_NAMES,
    Brand,
)
from phishlens.models import EmailAddress, Evidence, ParsedEmail, Signal

_DOTTED_ACRONYM = re.compile(r"\b(?:[a-z]\.){2,}[a-z]?")
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

_TECHNIQUE = {
    "homoglyph": "it swaps in look-alike characters",
    "typo": "it is a slight misspelling",
    "combo": "it adds extra words to the brand name",
    "tld_swap": "it uses the same name with a different ending",
}


def _contains_phrase(text: str, phrase: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", text) is not None


def brand_in_display_name(display_name: str) -> Brand | None:
    # Compare skeletons so "Micr0soft" and "Раураl" (Cyrillic) still match, and join
    # dotted acronyms so "D.H.L" matches "DHL".
    normalized = _DOTTED_ACRONYM.sub(lambda m: m.group(0).replace(".", ""), skeleton(display_name))
    for brand in BRANDS:
        if any(_contains_phrase(normalized, skeleton(p)) for p in brand.display_names):
            return brand
    return None


class SenderAnalyzer:
    name = "sender"

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        sender = email.from_
        findings: list[Finding] = []
        if sender is None or not sender.address:
            findings.append(self._missing(sender))
        if len(email.header_values("From")) > 1:
            findings.append(self._duplicate_from(email))
        if sender is not None:
            organization = organization_brand([a.domain for a in email.to])
            findings += self._display_name(sender)
            findings += self._organization_claims(sender, organization)
            findings += self._lookalike(sender, organization)
            findings += self._reply_to(sender, email.reply_to)
            findings += self._return_path(sender, email.return_path)
        return aggregate(self.name, findings, "addresses")

    @staticmethod
    def _missing(sender: EmailAddress | None) -> Finding:
        shown = sender.display_name if sender else "(no From header)"
        return Finding(
            "FROM_MISSING",
            "This email doesn't show a real sender address, which legitimate senders always "
            "include.",
            [Evidence(kind="sender", label="From", value=shown)],
        )

    @staticmethod
    def _duplicate_from(email: ParsedEmail) -> Finding:
        return Finding(
            "FROM_DUPLICATE",
            "This email lists more than one sender. Different email apps may show different "
            "ones, a trick used to disguise who really sent it.",
            [Evidence(kind="header", label="From", value=v) for v in email.header_values("From")],
        )

    @staticmethod
    def _display_name(sender: EmailAddress) -> list[Finding]:
        findings = []
        from_evidence = Evidence(kind="sender", label="Actual sender", value=sender.address or "-")
        name = sender.display_name
        sender_domain = registered_domain(sender.domain) if sender.domain else ""

        brand = brand_in_display_name(name) if name else None
        if brand and brand_for_domain(sender_domain) is not brand:
            findings.append(
                Finding(
                    "DISPLAY_NAME_BRAND_MISMATCH",
                    f"The sender's name says \"{name}\", but the email didn't come from "
                    f"{brand.name}; it came from {sender_domain or 'an unknown address'}.",
                    [Evidence(kind="sender", label="Name shown", value=name), from_evidence],
                )
            )

        shown_email = _EMAIL_IN_TEXT.search(name)
        if shown_email and registered_domain(shown_email.group(1)) != sender_domain:
            findings.append(
                Finding(
                    "DISPLAY_NAME_EMAIL_MISMATCH",
                    f'The sender\'s name shows the address "{shown_email.group(0)}", but the '
                    f"email actually came from {sender.address or 'somewhere else'}.",
                    [Evidence(kind="sender", label="Name shown", value=name), from_evidence],
                )
            )

        role = next((r for r in ROLE_DISPLAY_NAMES if _contains_phrase(name.lower(), r)), None)
        if role and sender_domain in FREEMAIL_DOMAINS:
            findings.append(
                Finding(
                    "DISPLAY_NAME_ROLE_FREEMAIL",
                    f'The sender calls themselves "{name}" but writes from a free personal '
                    f"{sender_domain} account. Real company staff and departments use their "
                    "company's email.",
                    [Evidence(kind="sender", label="Name shown", value=name), from_evidence],
                )
            )
        return findings

    @staticmethod
    def _organization_claims(
        sender: EmailAddress, organization: tuple[Brand, ...]
    ) -> list[Finding]:
        """A display name that claims to be the recipient's own organization or its IT/email
        staff, sent from an outside domain: the "your mailbox is full" pretext."""
        name = sender.display_name
        sender_domain = registered_domain(sender.domain) if sender.domain else ""
        if not organization or not name or sender_domain in FREEMAIL_DOMAINS:
            return []  # free-mail role names are covered by DISPLAY_NAME_ROLE_FREEMAIL
        org = organization[0]
        if sender_domain in org.domains or brand_for_domain(sender_domain):
            return []  # internal mail, or a real platform (DocuSign, Google) relaying for it
        normalized = skeleton(name)
        evidence = [
            Evidence(kind="sender", label="Name shown", value=name),
            Evidence(kind="sender", label="Actual sender", value=sender.address or "-"),
        ]
        # "acme-defense" also appears as "Acme Defense" or "AcmeDefense" in a display name.
        names = {skeleton(d) for d in org.domains}
        for label in org.labels:
            if len(label) >= 4:
                names |= {
                    skeleton(label),
                    skeleton(label.replace("-", " ")),
                    skeleton(label.replace("-", "")),
                }
        mentions_org = any(_contains_phrase(normalized, n) for n in names)
        if mentions_org:
            return [
                Finding(
                    "DISPLAY_NAME_ORG_MISMATCH",
                    f"The sender's name \"{name}\" uses your organization's name, but the email "
                    f"came from an outside domain, {sender_domain or 'unknown'}.",
                    evidence,
                )
            ]
        role = next((r for r in MAILBOX_ROLE_NAMES if _contains_phrase(name.lower(), r)), None)
        if role:
            return [
                Finding(
                    "DISPLAY_NAME_ROLE_EXTERNAL",
                    f'The sender calls themselves "{name}", as if they run your email or IT, but '
                    f"the email came from an outside domain, {sender_domain or 'unknown'}.",
                    evidence,
                )
            ]
        return []

    @staticmethod
    def _lookalike(sender: EmailAddress, organization: tuple[Brand, ...]) -> list[Finding]:
        if not sender.domain:
            return []
        lookalike = find_lookalike(sender.domain, organization)
        if lookalike is None:
            return []
        return [
            Finding(
                "SENDER_DOMAIN_LOOKALIKE",
                f"The sender's domain {registered_domain(sender.domain)} imitates "
                f"{lookalike.brand.name}'s real domain {lookalike.real_domain}: "
                f"{_TECHNIQUE[lookalike.technique]}.",
                [
                    Evidence(kind="sender", label="Sender domain", value=sender.domain),
                    Evidence(kind="sender", label="Real domain", value=lookalike.real_domain),
                ],
            )
        ]

    @staticmethod
    def _reply_to(sender: EmailAddress, reply_to: list[EmailAddress]) -> list[Finding]:
        sender_domain = registered_domain(sender.domain) if sender.domain else ""
        for address in reply_to:
            reply_domain = registered_domain(address.domain) if address.domain else ""
            if not reply_domain or reply_domain == sender_domain:
                continue
            to_freemail = reply_domain in FREEMAIL_DOMAINS and sender_domain not in FREEMAIL_DOMAINS
            return [
                Finding(
                    "REPLY_TO_FREEMAIL" if to_freemail else "REPLY_TO_MISMATCH",
                    f"If you reply, your answer goes to {address.address}"
                    f"{', a free personal account,' if to_freemail else ''} instead of the "
                    f"sender's domain {sender_domain or '(unknown)'}. Scammers do this so replies "
                    "reach them.",
                    [
                        Evidence(kind="sender", label="From", value=sender.address or "-"),
                        Evidence(kind="sender", label="Replies go to", value=address.address),
                    ],
                )
            ]
        return []

    @staticmethod
    def _return_path(sender: EmailAddress, return_path: EmailAddress | None) -> list[Finding]:
        if not return_path or not return_path.domain or not sender.domain:
            return []
        bounce_domain = registered_domain(return_path.domain)
        if bounce_domain == registered_domain(sender.domain):
            return []
        return [
            Finding(
                "RETURN_PATH_MISMATCH",
                f"The email's technical return address uses {bounce_domain}, not the sender's "
                "domain. This is normal for newsletters and mailing services, but spoofers do it "
                "too.",
                [
                    Evidence(kind="sender", label="From", value=sender.address),
                    Evidence(kind="header", label="Return-Path", value=return_path.address),
                ],
            )
        ]
