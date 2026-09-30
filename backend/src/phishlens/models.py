"""Data contracts shared by every stage of the pipeline.

raw email -> ParsedEmail -> analyzers -> Signal[] -> scoring -> Verdict

Everything downstream of the parser only sees these types, so parsers,
analyzers, the scorer and the API can be built and tested independently.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


class _Contract(BaseModel):
    # Immutable and strict: a typo'd field name is a bug, not silently dropped data.
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------
# ParsedEmail
# --------------------------------------------------------------------------


class EmailAddress(_Contract):
    display_name: str = ""
    address: str

    @property
    def domain(self) -> str:
        """Lowercased part after the last '@', or '' if the address has none."""
        _, sep, domain = self.address.rpartition("@")
        return domain.lower().rstrip(".") if sep else ""


class Header(_Contract):
    name: str
    value: str


UrlSource = Literal["html_anchor", "html_form", "html_other", "text"]


class ExtractedUrl(_Contract):
    href: str
    """Where the link actually goes, exactly as written in the email."""
    visible_text: str | None = None
    """What the reader sees. None when there is no link text (bare URL, form action)."""
    source: UrlSource


class Attachment(_Contract):
    filename: str | None
    content_type: str
    """MIME type as declared by the sender, which may lie about the file."""
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    is_inline: bool = False


class ParsedEmail(_Contract):
    headers: list[Header] = Field(default_factory=list)
    """All headers in original order. Duplicates (Received, Authentication-Results) are kept."""

    message_id: str | None = None
    subject: str = ""
    date: str | None = None

    from_: EmailAddress | None = Field(default=None, alias="from")
    reply_to: list[EmailAddress] = Field(default_factory=list)
    return_path: EmailAddress | None = None
    to: list[EmailAddress] = Field(default_factory=list)

    text_body: str = ""
    html_body: str = ""
    urls: list[ExtractedUrl] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)

    parse_warnings: list[str] = Field(default_factory=list)
    """Malformed structure the parser recovered from. Useful as evidence on its own."""

    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    def header_values(self, name: str) -> list[str]:
        """All values of a header, case-insensitively, in original order."""
        lname = name.lower()
        return [h.value for h in self.headers if h.name.lower() == lname]


# --------------------------------------------------------------------------
# Signal
# --------------------------------------------------------------------------


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}

EvidenceKind = Literal["header", "sender", "url", "attachment", "body"]


class Evidence(_Contract):
    """One concrete thing the user can look at to verify a signal themselves.

    A link mismatch is two Evidence items ("Link text" / "Actually goes to")
    so the UI can render them side by side.
    """

    kind: EvidenceKind
    label: str
    value: str


class Signal(_Contract):
    analyzer: str
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")
    """Stable machine id, e.g. SPF_FAIL. Weights are configured per id."""
    severity: Severity
    weight: float = Field(ge=-100, le=100)
    """Contribution to the risk score. Negative = evidence of legitimacy (e.g. DMARC pass)."""
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str = Field(min_length=1)
    """One plain-English sentence a non-technical employee can understand."""


# --------------------------------------------------------------------------
# Analyzer interface
# --------------------------------------------------------------------------


class AnalyzerStatus(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    """Dependency down, timed out, or not configured (e.g. no LLM API key)."""
    ERROR = "error"
    """Analyzer crashed. The verdict is still produced from the others."""


class AnalyzerReport(_Contract):
    analyzer: str
    status: AnalyzerStatus
    detail: str | None = None


class AnalyzerUnavailable(Exception):
    """Raised by an analyzer whose dependency is missing or down. The message is shown
    to the user, so keep it free of secrets and internals."""


class Analyzer(Protocol):
    name: str

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        """Return signals, or raise AnalyzerUnavailable. Must not modify the email."""
        ...


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------


class Label(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


class EmailSummary(_Contract):
    """Just enough of the email for the UI to show what was analyzed."""

    subject: str
    from_display: str
    from_address: str
    url_count: int
    attachment_count: int
    warnings: list[str] = Field(default_factory=list)
    """Problems the parser recovered from, e.g. no headers because only the body was pasted."""


class Verdict(_Contract):
    label: Label
    score: float = Field(ge=0, le=100)
    signals: list[Signal]
    """All signals, sorted most severe first."""
    summary: str
    recommended_actions: list[str]
    override: str | None = None
    """Set when a hard rule forced the label (e.g. URL on a threat feed), naming the rule."""
    analyzers: list[AnalyzerReport] = Field(default_factory=list)
    email: EmailSummary
