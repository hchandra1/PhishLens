"""How long ago the sender's and links' domains were registered (RDAP).

Phishing campaigns burn through freshly registered domains, so age is one of the
strongest cheap signals. RDAP is the registries' structured successor to WHOIS;
rdap.org redirects each query to the right registry. Only the domain name is sent.
Opt-in with PHISHLENS_RDAP=on.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime

import httpx2

from phishlens.analyzers._common import Finding, aggregate
from phishlens.analyzers._network import (
    TTLCache,
    make_client,
    partial_results,
    run_lookups,
)
from phishlens.analyzers.urls import parse_href
from phishlens.domains import is_ip_address, is_known_domain, organization_brand, split_host
from phishlens.models import AnalyzerUnavailable, Evidence, ParsedEmail, Signal

SERVICE = "The domain registration lookup"
RDAP_BASE = "https://rdap.org"
NEW_DAYS = 30
RECENT_DAYS = 90
MAX_DOMAINS = 6
DEADLINE_SECONDS = 8.0

# Registration dates don't change; a day is plenty.
_CACHE = TTLCache(ttl_seconds=24 * 3600)


class DomainAgeAnalyzer:
    name = "domain_age"

    def __init__(
        self,
        client: httpx2.Client | None = None,
        enabled: bool | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        cache: TTLCache = _CACHE,
    ) -> None:
        self.enabled = (
            enabled if enabled is not None else os.environ.get("PHISHLENS_RDAP", "").lower() == "on"
        )
        self._client, self._now, self._cache = client, now, cache

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        if not self.enabled:
            raise AnalyzerUnavailable("Domain age lookups are turned off (set PHISHLENS_RDAP=on).")
        domains = candidate_domains(email)
        results = partial_results(
            SERVICE, run_lookups(list(domains), self._registered_on, DEADLINE_SECONDS)
        )
        findings = []
        for domain, registered in results.items():
            if registered is None:
                continue  # registry has no RDAP record for it; unknown, not suspicious
            finding = self._judge(domain, domains[domain], registered)
            if finding:
                findings.append(finding)
        return aggregate(self.name, findings, "domains")

    def _judge(self, domain: str, role: str, registered: datetime) -> Finding | None:
        age = (self._now() - registered).days
        if age >= RECENT_DAYS:
            return None
        where = "The sender's domain" if role == "sender" else f"A link's site ({domain})"
        if role == "sender":
            where += f" ({domain})"
        when = "today" if age <= 0 else f"only {age} day{'s' if age != 1 else ''} ago"
        return Finding(
            "DOMAIN_NEWLY_REGISTERED" if age < NEW_DAYS else "DOMAIN_RECENTLY_REGISTERED",
            f"{where} was registered {when}. Scammers use brand-new domains because old ones "
            "get blocked; established companies rarely do.",
            [
                Evidence(
                    kind="sender" if role == "sender" else "url", label="Domain", value=domain
                ),
                Evidence(kind="header", label="Registered on", value=registered.date().isoformat()),
            ],
        )

    def _registered_on(self, domain: str) -> datetime | None:
        return self._cache.cached(("rdap", domain), lambda: self._fetch(domain))

    def _http(self) -> httpx2.Client:
        # One pooled client per analyzer, created on first use (it is thread-safe).
        if self._client is None:
            self._client = make_client()
        return self._client

    def _fetch(self, domain: str) -> datetime | None:
        client = self._http()
        response = client.get(f"{RDAP_BASE}/domain/{domain}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return registration_date(response.json())


def registration_date(rdap: dict) -> datetime | None:
    for event in rdap.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            parsed = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def candidate_domains(email: ParsedEmail) -> dict[str, str]:
    """Registered domains worth looking up, sender first: {domain: 'sender' | 'link'}."""
    organization = organization_brand([a.domain for a in email.to])
    own = {d for b in organization for d in b.domains}
    hosts: list[tuple[str, str]] = []
    if email.from_ and email.from_.domain:
        hosts.append((email.from_.domain, "sender"))
    for url in email.urls:
        _, parts = parse_href(url.href)
        if parts is not None and parts.hostname:
            hosts.append((parts.hostname, "link"))

    domains: dict[str, str] = {}
    for host, role in hosts:
        parts = split_host(host)
        registered = parts.registered
        if (
            not parts.suffix
            or is_ip_address(host)
            or is_known_domain(registered)
            or registered in own
            or registered in domains
        ):
            continue
        domains[registered] = role
        if len(domains) >= MAX_DOMAINS:
            break
    return domains
