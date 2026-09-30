"""Turns scored signals into a plain-English summary and concrete next steps.

Written for a non-technical employee deciding what to do with one email.
"""

from __future__ import annotations

from phishlens.catalog import load_catalog
from phishlens.models import Label, Severity, Signal

MAX_REASONS = 3

_HEADLINES = {
    Label.PHISHING: "This email is very likely a phishing attempt.",
    Label.SUSPICIOUS: "This email has warning signs. Treat it with caution until you verify it.",
    Label.SAFE: "We didn't find signs of phishing in this email.",
}


def sort_signals(signals: list[Signal]) -> list[Signal]:
    """Most severe first; trust signals (negative weight) last."""
    return sorted(signals, key=lambda s: (s.weight < 0, -s.severity.rank, -s.weight))


def build_summary(label: Label, signals: list[Signal], override: str | None) -> str:
    catalog = load_catalog()
    warnings = [s for s in sort_signals(signals) if s.weight > 0]
    trust = [s for s in signals if s.weight < 0]
    parts = [_HEADLINES[label]]

    if override:
        parts.append(override)
    if label == Label.SAFE:
        if trust:
            parts.append(f"It {_join([catalog[s.id].reason for s in trust])}.")
        minor = [s for s in warnings if s.severity != Severity.INFO]
        if minor:
            parts.append(f"Minor note: it {_join([catalog[s.id].reason for s in minor[:2]])}.")
        parts.append(
            "No automated check is perfect: if it unexpectedly asks for passwords, payments, or "
            "urgent action, verify it first."
        )
    elif warnings:
        # Informational notes only make the headline when there is nothing stronger.
        headline = [s for s in warnings if s.severity != Severity.INFO] or warnings
        reasons = [catalog[s.id].reason for s in headline[:MAX_REASONS]]
        more = len(headline) - MAX_REASONS
        tail = (
            f" (plus {more} more warning sign{'s' if more > 1 else ''} below)" if more > 0 else ""
        )
        parts.append(f"It {_join(reasons)}{tail}.")
    return " ".join(parts)


def recommended_actions(
    label: Label, signals: list[Signal], has_links: bool, has_attachments: bool
) -> list[str]:
    if label == Label.SAFE:
        return ["No action needed."]

    ids = {s.id for s in signals if s.weight > 0}
    phishing = label == Label.PHISHING
    actions = []
    if has_links:
        actions.append(
            "Don't click any links. If you need the website, type its address into your "
            "browser yourself."
        )
    if has_attachments:
        actions.append("Don't open any attachments.")
    if phishing or ids & {"REPLY_TO_FREEMAIL", "REPLY_TO_MISMATCH"}:
        actions.append("Don't reply. Your reply may go to the attacker, not the real sender.")
    if phishing:
        actions.append("Report it to your IT or security contact, then delete it.")
        actions.append(
            "If you already clicked a link, opened a file, or entered a password, tell IT right "
            "away and change that password."
        )
    else:
        actions.append(
            "Verify it through a channel you already trust: call the sender at a number you "
            "already have, not one from this email."
        )
        actions.append("If you're unsure, forward it to your IT or security contact and ask.")
    return actions


def _join(items: list[str]) -> str:
    if len(items) <= 2:
        return " and ".join(items)
    return f"{', '.join(items[:-1])}, and {items[-1]}"
