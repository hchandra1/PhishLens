"""Runs the analyzers on one email and assembles the Verdict.

raw email -> parse -> analyzers (in parallel) -> scoring -> explanation -> Verdict
"""

from __future__ import annotations

import logging
from concurrent.futures import Future, ThreadPoolExecutor, wait

from phishlens.analyzers import default_analyzers
from phishlens.explain import build_summary, recommended_actions, sort_signals
from phishlens.models import (
    Analyzer,
    AnalyzerReport,
    AnalyzerStatus,
    AnalyzerUnavailable,
    EmailSummary,
    ParsedEmail,
    Severity,
    Signal,
    Verdict,
)
from phishlens.parser import parse_email
from phishlens.scoring import ScoringConfig, score_signals

logger = logging.getLogger(__name__)

DEFAULT_DEADLINE_SECONDS = 15.0


def analyze(
    email: ParsedEmail,
    analyzers: list[Analyzer] | None = None,
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    scoring: ScoringConfig | None = None,
) -> Verdict:
    """Analyze an email. A failing or slow analyzer never prevents a verdict."""
    analyzers = default_analyzers() if analyzers is None else analyzers
    signals, reports = _run_all(email, analyzers, deadline_seconds)

    scored = score_signals(signals, scoring)
    ordered = sort_signals(_mark_uncounted(signals, scored.counted))
    sender = email.from_
    return Verdict(
        label=scored.label,
        score=scored.score,
        signals=ordered,
        summary=build_summary(scored.label, scored.counted, scored.override),
        recommended_actions=recommended_actions(
            scored.label,
            scored.counted,
            has_links=bool(email.urls),
            has_attachments=any(not a.is_inline for a in email.attachments),
        ),
        override=scored.override,
        analyzers=reports,
        email=EmailSummary(
            subject=email.subject,
            from_display=sender.display_name if sender else "",
            from_address=sender.address if sender else "",
            url_count=len(email.urls),
            attachment_count=len(email.attachments),
            warnings=email.parse_warnings,
        ),
    )


def _mark_uncounted(signals: list[Signal], counted: list[Signal]) -> list[Signal]:
    """Show signals the scorer set aside (e.g. a DMARC pass next to a look-alike domain)
    as neutral notes, so the UI never presents them as reassuring."""
    kept = {id(s) for s in counted}
    return [
        s
        if id(s) in kept
        else s.model_copy(
            update={
                "weight": 0,
                "severity": Severity.INFO,
                "explanation": f"{s.explanation} Not counted here, because the warning signs "
                "above outweigh it.",
            }
        )
        for s in signals
    ]


def analyze_raw(raw: bytes | str, **kwargs) -> Verdict:
    return analyze(parse_email(raw), **kwargs)


def _run_all(
    email: ParsedEmail, analyzers: list[Analyzer], deadline_seconds: float
) -> tuple[list[Signal], list[AnalyzerReport]]:
    executor = ThreadPoolExecutor(max_workers=max(1, len(analyzers)), thread_name_prefix="analyzer")
    try:
        futures = {executor.submit(a.analyze, email): a for a in analyzers}
        wait(futures, timeout=deadline_seconds)
        signals: list[Signal] = []
        reports = []
        for future, analyzer in futures.items():
            found, report = _collect(future, analyzer)
            signals += found
            reports.append(report)
        return signals, reports
    finally:
        # Don't block the response on a hung analyzer. Python can't kill a thread, so
        # network-bound analyzers must also enforce their own timeouts.
        executor.shutdown(wait=False, cancel_futures=True)


def _collect(future: Future, analyzer: Analyzer) -> tuple[list[Signal], AnalyzerReport]:
    name = analyzer.name
    if not future.done():
        return [], AnalyzerReport(
            analyzer=name, status=AnalyzerStatus.UNAVAILABLE, detail="Timed out."
        )
    try:
        signals = future.result()
    except AnalyzerUnavailable as exc:
        return [], AnalyzerReport(analyzer=name, status=AnalyzerStatus.UNAVAILABLE, detail=str(exc))
    except Exception:
        # Log details for operators; show users only that this check didn't run.
        logger.exception("analyzer %s failed", name)
        return [], AnalyzerReport(
            analyzer=name, status=AnalyzerStatus.ERROR, detail="This check failed to run."
        )
    return signals, AnalyzerReport(analyzer=name, status=AnalyzerStatus.OK)
