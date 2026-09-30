from __future__ import annotations

from dataclasses import dataclass

from phishlens.catalog import make_signal
from phishlens.models import Evidence, Signal

MAX_EXAMPLES = 3


@dataclass(frozen=True)
class Finding:
    signal_id: str
    explanation: str
    evidence: list[Evidence]


def aggregate(analyzer: str, findings: list[Finding], noun: str | None) -> list[Signal]:
    """One signal per id, however many links or files triggered it.

    Forty tracked links in a newsletter are one problem, not forty, so repeats
    add evidence (up to MAX_EXAMPLES) but never add weight. With a noun, the
    explanation notes how many other items had the same problem.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.signal_id, []).append(finding)

    signals = []
    for signal_id, group in grouped.items():
        explanation = group[0].explanation
        if noun and len(group) > 1:
            others = len(group) - 1
            explanation += f" {others} other {noun if others > 1 else noun.rstrip('s')} "
            explanation += "have the same problem." if others > 1 else "has the same problem."
        evidence = [e for f in group[:MAX_EXAMPLES] for e in f.evidence]
        signals.append(make_signal(analyzer, signal_id, explanation, evidence))
    return signals
