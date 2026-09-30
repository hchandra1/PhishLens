"""SPF / DKIM / DMARC results, read from the Authentication-Results header.

Security note: Authentication-Results is only trustworthy when written by *your*
mail server. Anyone can put a fake "dmarc=pass" header in the message they send.
Receiving servers prepend their header, so we use the topmost one, or, when
trusted_authserv_ids is configured, the first one written by a listed server.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from phishlens.analyzers._common import Finding, aggregate
from phishlens.domains import registered_domain
from phishlens.models import Evidence, ParsedEmail, Signal

_COMMENT = re.compile(r"\([^()]*\)")
_METHOD_RESULT = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z]+)", re.IGNORECASE)
_PROPERTY = re.compile(r"([a-z0-9_-]+\.[a-z0-9_-]+)\s*=\s*([^\s;]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthResult:
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)
    text: str = ""


@dataclass(frozen=True)
class AuthResultsHeader:
    authserv_id: str
    results: list[AuthResult]
    raw: str

    def get(self, method: str) -> list[AuthResult]:
        return [r for r in self.results if r.method == method]


def parse_authentication_results(value: str) -> AuthResultsHeader:
    """Parse an RFC 8601 Authentication-Results header value."""
    cleaned = _COMMENT.sub("", value)
    authserv, *segments = cleaned.split(";")
    if _METHOD_RESULT.match(authserv):
        # Microsoft 365 omits the authserv-id and starts directly with "spf=...".
        authserv, segments = "", [authserv, *segments]
    results = []
    for segment in segments:
        # Each segment starts with its own method=result, so text inside a property
        # (e.g. an attacker-chosen smtp.mailfrom) can't be mistaken for a result.
        match = _METHOD_RESULT.match(segment)
        if not match:
            continue
        properties = {k.lower(): v.lower() for k, v in _PROPERTY.findall(segment)}
        results.append(
            AuthResult(
                method=match.group(1).lower(),
                result=match.group(2).lower(),
                properties=properties,
                text=" ".join(segment.split()),
            )
        )
    authserv_id = authserv.split()[0].lower() if authserv.split() else ""
    return AuthResultsHeader(authserv_id, results, " ".join(value.split()))


class AuthAnalyzer:
    name = "auth"

    def __init__(self, trusted_authserv_ids: list[str] | None = None) -> None:
        if trusted_authserv_ids is None:
            configured = os.environ.get("PHISHLENS_TRUSTED_AUTHSERV_IDS", "")
            trusted_authserv_ids = [s.strip() for s in configured.split(",") if s.strip()]
        self.trusted_authserv_ids = [s.lower() for s in trusted_authserv_ids]

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        header = self._trusted_header(email)
        if header is None:
            return aggregate(self.name, [self._missing()], "headers")

        from_domain = email.from_.domain if email.from_ else ""
        dmarc = header.get("dmarc")
        dmarc_result = dmarc[0].result if dmarc else None
        evidence = [Evidence(kind="header", label="Checked by", value=header.authserv_id)]

        # DMARC already combines SPF and DKIM for the From domain. When it gives a
        # verdict, SPF and DKIM are shown as evidence but not scored a second time.
        if dmarc_result == "fail":
            findings = [
                Finding(
                    "DMARC_FAIL",
                    f"This email claims to be from {from_domain or 'a company'}, but it failed "
                    "that domain's own anti-forgery check (DMARC), so it was probably sent by "
                    "someone pretending to be them.",
                    [*evidence, *self._results_evidence(header)],
                )
            ]
        elif dmarc_result == "pass" and self._aligned(dmarc[0], from_domain):
            findings = [
                Finding(
                    "DMARC_PASS",
                    f"The email passed {from_domain}'s anti-forgery check (DMARC), so it really "
                    f"came from {from_domain}. That confirms who sent it, not that they are "
                    "trustworthy.",
                    [*evidence, Evidence(kind="header", label="DMARC", value=dmarc[0].text)],
                )
            ]
        else:
            findings = self._spf_dkim(header, evidence)
        return aggregate(self.name, findings, "headers")

    def _trusted_header(self, email: ParsedEmail) -> AuthResultsHeader | None:
        headers = [
            parse_authentication_results(v) for v in email.header_values("Authentication-Results")
        ]
        if not self.trusted_authserv_ids:
            return headers[0] if headers else None
        return next((h for h in headers if h.authserv_id in self.trusted_authserv_ids), None)

    def _missing(self) -> Finding:
        where = "your mail server's" if self.trusted_authserv_ids else "the receiving mail server's"
        return Finding(
            "AUTH_RESULTS_MISSING",
            f"This email doesn't include {where} sender checks (SPF, DKIM, DMARC), so we can't "
            "confirm who really sent it.",
            [Evidence(kind="header", label="Authentication-Results", value="(not present)")],
        )

    @staticmethod
    def _aligned(dmarc: AuthResult, from_domain: str) -> bool:
        """The DMARC pass must be for the domain the reader sees in From."""
        checked = dmarc.properties.get("header.from")
        return (
            not checked
            or not from_domain
            or (registered_domain(checked) == registered_domain(from_domain))
        )

    @staticmethod
    def _results_evidence(header: AuthResultsHeader) -> list[Evidence]:
        return [
            Evidence(kind="header", label=r.method.upper(), value=r.text)
            for r in header.results
            if r.method in ("spf", "dkim", "dmarc")
        ]

    def _spf_dkim(self, header: AuthResultsHeader, evidence: list[Evidence]) -> list[Finding]:
        findings = []
        spf = header.get("spf")
        if spf and spf[0].result in ("fail", "softfail"):
            sender = spf[0].properties.get("smtp.mailfrom", "").rpartition("@")[2] or "the sender"
            hard = spf[0].result == "fail"
            findings.append(
                Finding(
                    "SPF_FAIL" if hard else "SPF_SOFTFAIL",
                    f"The server that sent this email is {'not' if hard else 'not fully'} "
                    f"approved to send mail for {sender}.",
                    [*evidence, Evidence(kind="header", label="SPF", value=spf[0].text)],
                )
            )
        dkim = header.get("dkim")
        if dkim and not any(r.result == "pass" for r in dkim):
            failed = next((r for r in dkim if r.result == "fail"), None)
            if failed:
                findings.append(
                    Finding(
                        "DKIM_FAIL",
                        "The email's digital signature doesn't match its contents, so it may "
                        "have been altered or forged.",
                        [*evidence, Evidence(kind="header", label="DKIM", value=failed.text)],
                    )
                )
        return findings
