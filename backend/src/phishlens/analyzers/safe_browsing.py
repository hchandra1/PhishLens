"""Links checked against Google Safe Browsing's lists of phishing and malware sites.

Only URLs are sent, never fetched. Query strings and fragments are removed first:
they often carry the recipient's email address or a sign-in token, and Safe
Browsing's matching works on host and path. Enabled by GOOGLE_SAFE_BROWSING_API_KEY.
"""

from __future__ import annotations

import os
from urllib.parse import urlunsplit

import httpx2

from phishlens.analyzers._common import Finding, aggregate
from phishlens.analyzers._network import TTLCache, make_client, unavailable
from phishlens.analyzers.urls import parse_href
from phishlens.models import AnalyzerUnavailable, Evidence, ParsedEmail, Signal

SERVICE = "Google Safe Browsing"
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
MAX_URLS = 50
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]
_DESCRIPTIONS = {
    "SOCIAL_ENGINEERING": "a phishing or scam site",
    "MALWARE": "a site that spreads malware",
    "UNWANTED_SOFTWARE": "a site that distributes unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "a site that distributes harmful apps",
}
_NO_THREAT = ""

# Lists change quickly, so keep results briefly.
_CACHE = TTLCache(ttl_seconds=30 * 60)


def lookup_url(href: str) -> str | None:
    """The form of a link that is sent: scheme, host and path only."""
    scheme, parts = parse_href(href)
    if parts is None or not parts.hostname or scheme not in ("http", "https"):
        return None
    return urlunsplit((scheme, parts.netloc.rpartition("@")[2].lower(), parts.path or "/", "", ""))


class SafeBrowsingAnalyzer:
    name = "safe_browsing"

    def __init__(
        self,
        client: httpx2.Client | None = None,
        api_key: str | None = None,
        cache: TTLCache = _CACHE,
    ) -> None:
        self.api_key = api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        self._client, self._cache = client, cache

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        if not self.api_key:
            raise AnalyzerUnavailable(
                "Safe Browsing lookups aren't configured (set GOOGLE_SAFE_BROWSING_API_KEY)."
            )
        originals: dict[str, list[str]] = {}
        for url in email.urls:
            sent = lookup_url(url.href)
            if sent:
                originals.setdefault(sent, []).append(url.href)
        threats = self._threats(list(originals)[:MAX_URLS])

        findings = [
            Finding(
                "URL_THREAT_FEED",
                f"Google Safe Browsing lists a link in this email as "
                f"{_DESCRIPTIONS.get(threat, 'a dangerous site')}.",
                [Evidence(kind="url", label="Listed link", value=originals[sent][0])],
            )
            for sent, threat in threats.items()
            if threat
        ]
        return aggregate(self.name, findings, "links")

    def _threats(self, urls: list[str]) -> dict[str, str]:
        results = {u: self._cache.get(("sb", u), None) for u in urls}
        todo = [u for u, cached in results.items() if cached is None]
        if todo:
            try:
                found = self._query(todo)
            except httpx2.HTTPError as exc:
                raise unavailable(SERVICE, exc) from exc
            except (ValueError, KeyError, TypeError) as exc:
                raise AnalyzerUnavailable(f"{SERVICE} returned an unexpected response.") from exc
            for url in todo:
                results[url] = found.get(url, _NO_THREAT)
                self._cache.set(("sb", url), results[url])
        return results  # type: ignore[return-value]

    def _http(self) -> httpx2.Client:
        # One pooled client per analyzer, created on first use (it is thread-safe).
        if self._client is None:
            self._client = make_client()
        return self._client

    def _query(self, urls: list[str]) -> dict[str, str]:
        client = self._http()
        response = client.post(
            ENDPOINT,
            params={"key": self.api_key},
            json={
                "client": {"clientId": "phishlens", "clientVersion": "0.1.0"},
                "threatInfo": {
                    "threatTypes": THREAT_TYPES,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in urls],
                },
            },
        )
        response.raise_for_status()
        return {m["threat"]["url"]: m["threatType"] for m in response.json().get("matches", [])}
