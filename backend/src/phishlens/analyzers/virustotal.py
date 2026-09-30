"""Attachment hashes checked against VirusTotal's antivirus results.

Only the SHA-256 hash is sent. Files are never uploaded: an upload would share a
possibly confidential document with every VirusTotal subscriber. Enabled by
VIRUSTOTAL_API_KEY. The free tier allows 4 lookups a minute, so results are cached
and only the first few attachments are checked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx2

from phishlens.analyzers._common import Finding, aggregate
from phishlens.analyzers._network import (
    TTLCache,
    make_client,
    partial_results,
    run_lookups,
)
from phishlens.models import AnalyzerUnavailable, Attachment, Evidence, ParsedEmail, Signal

SERVICE = "VirusTotal"
ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"
MALWARE_THRESHOLD = 3  # engines; one or two detections are often false positives
MAX_FILES = 4
DEADLINE_SECONDS = 8.0

_CACHE = TTLCache(ttl_seconds=6 * 3600)


@dataclass(frozen=True)
class Detections:
    malicious: int
    total: int


class VirusTotalAnalyzer:
    name = "virustotal"

    def __init__(
        self,
        client: httpx2.Client | None = None,
        api_key: str | None = None,
        cache: TTLCache = _CACHE,
    ) -> None:
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self._client, self._cache = client, cache

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        if not self.api_key:
            raise AnalyzerUnavailable(
                "VirusTotal lookups aren't configured (set VIRUSTOTAL_API_KEY)."
            )
        files: dict[str, Attachment] = {}
        for attachment in email.attachments:
            if attachment.size > 0 and attachment.sha256 not in files:
                files[attachment.sha256] = attachment
        hashes = list(files)[:MAX_FILES]
        results = partial_results(SERVICE, run_lookups(hashes, self._detections, DEADLINE_SECONDS))

        findings = []
        for sha256, detections in results.items():
            if detections is None or detections.malicious == 0:
                continue  # unknown to VirusTotal, or clean
            name = files[sha256].filename or "an attachment"
            known = detections.malicious >= MALWARE_THRESHOLD
            findings.append(
                Finding(
                    "ATTACHMENT_KNOWN_MALWARE" if known else "ATTACHMENT_SOME_DETECTIONS",
                    f"{detections.malicious} of {detections.total} antivirus engines on "
                    f'VirusTotal flag "{name}" as malicious'
                    + (". Do not open it." if known else ", which may be a false alarm."),
                    [
                        Evidence(kind="attachment", label="File", value=name),
                        Evidence(kind="attachment", label="SHA-256", value=sha256),
                    ],
                )
            )
        return aggregate(self.name, findings, "attachments")

    def _detections(self, sha256: str) -> Detections | None:
        return self._cache.cached(("vt", sha256), lambda: self._fetch(sha256))

    def _http(self) -> httpx2.Client:
        # One pooled client per analyzer, created on first use (it is thread-safe).
        if self._client is None:
            self._client = make_client()
        return self._client

    def _fetch(self, sha256: str) -> Detections | None:
        client = self._http()
        response = client.get(ENDPOINT.format(sha256=sha256), headers={"x-apikey": self.api_key})
        if response.status_code == 404:
            return None  # never seen: unknown, not clean
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return Detections(malicious=int(stats.get("malicious", 0)), total=sum(stats.values()))
