"""Analyzers each take a ParsedEmail and return Signals.

The first five are deterministic and offline. The rest call external services and are
opt-in; when not configured they report "unavailable" and the verdict is built without them.
"""

from phishlens.analyzers.attachments import AttachmentAnalyzer
from phishlens.analyzers.auth import AuthAnalyzer
from phishlens.analyzers.content import ContentAnalyzer
from phishlens.analyzers.domain_age import DomainAgeAnalyzer
from phishlens.analyzers.llm import LlmContentAnalyzer
from phishlens.analyzers.safe_browsing import SafeBrowsingAnalyzer
from phishlens.analyzers.sender import SenderAnalyzer
from phishlens.analyzers.urls import UrlAnalyzer
from phishlens.analyzers.virustotal import VirusTotalAnalyzer
from phishlens.models import Analyzer

__all__ = [
    "AttachmentAnalyzer",
    "AuthAnalyzer",
    "ContentAnalyzer",
    "DomainAgeAnalyzer",
    "LlmContentAnalyzer",
    "SafeBrowsingAnalyzer",
    "SenderAnalyzer",
    "UrlAnalyzer",
    "VirusTotalAnalyzer",
    "default_analyzers",
    "offline_analyzers",
]


def offline_analyzers() -> list[Analyzer]:
    """Deterministic checks that need no network or credentials."""
    return [
        AuthAnalyzer(),
        SenderAnalyzer(),
        UrlAnalyzer(),
        AttachmentAnalyzer(),
        ContentAnalyzer(),
    ]


def default_analyzers() -> list[Analyzer]:
    return [
        *offline_analyzers(),
        LlmContentAnalyzer(),
        DomainAgeAnalyzer(),
        SafeBrowsingAnalyzer(),
        VirusTotalAnalyzer(),
    ]
