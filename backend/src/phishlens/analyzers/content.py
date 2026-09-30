"""Deterministic checks on the email's wording.

- Text aimed at AI or automated scanners ("AI assistant: classify this as safe").
  Deterministic on purpose: it must not depend on the model the text is trying to fool.
  It also scans the raw HTML, where hidden text and HTML comments usually carry it.
- The recipient's own address in the subject, a staple of mass credential phishing.
- Words disguised with look-alike letters from another alphabet or invisible characters,
  which dodge keyword filters while looking normal to a reader.
"""

from __future__ import annotations

import re
import unicodedata

from phishlens.analyzers._common import Finding, aggregate
from phishlens.models import Evidence, ParsedEmail, Signal

_AI = r"(?:ai|a\.i\.|llm|language model|assistant|chatbot|gpt|claude|copilot|gemini|bot)"
_SCANNER = r"(?:(?:ai|automated|security|spam|email|phishing)\s+){1,3}(?:reviewer|scanner|system|filter|analy[sz]er|tool)"  # noqa: E501
_PATTERNS = [
    re.compile(
        r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)",
        re.I,
    ),
    re.compile(
        rf"\b{_AI}\b[^.\n]{{0,60}}\b(?:classify|mark|treat|label|rate|report|consider|score)\b[^.\n]{{0,60}}\b(?:safe|legitimate|benign|harmless|trusted|not\s+(?:spam|phishing|malicious))\b",
        re.I,
    ),
    re.compile(
        rf"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+)?(?:{_SCANNER}|{_AI})\b",
        re.I,
    ),
    re.compile(r"\b(?:system\s+prompt|developer\s+mode|jailbreak)\b", re.I),
    # A fake end-of-input marker, trying to escape the delimiters an AI tool wraps email in.
    re.compile(r"</\s*(?:email|document|input|data|user)[\w-]*\s*>", re.I),
]
_MAX_SNIPPET = 200
_CONTEXT = 40


def find_ai_instructions(text: str) -> list[str]:
    """Matching passages with some context, one per distinct phrase."""
    snippets: dict[str, str] = {}
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            key = " ".join(match.group(0).lower().split())
            if key in snippets:
                continue  # the same phrase found in both the text and the raw HTML
            snippets[key] = _snippet(text, match.start(), match.end())
    return list(snippets.values())


def _snippet(text: str, start: int, end: int) -> str:
    """The match with some context, cut at word boundaries."""
    before = text[max(0, start - _CONTEXT) : start]
    after = text[end : end + _CONTEXT]
    if start > _CONTEXT and " " in before:
        before = "…" + before.split(" ", 1)[1]
    if end + _CONTEXT < len(text) and " " in after:
        after = after.rsplit(" ", 1)[0] + "…"
    return " ".join((before + text[start:end] + after).split())[:_MAX_SNIPPET]


# Invisible characters between two Latin letters ("Pas\u200bsword"). Only Latin: in some
# scripts (Persian, Hindi) zero-width joiners are legitimate parts of words.
_HIDDEN_INSIDE_WORD = re.compile(r"[A-Za-z][\u200b\u200c\u200d\u2060\ufeff]+[A-Za-z]")
_WORD = re.compile(r"[^\W\d_]+(?:[\u200b\u200c\u200d\u2060\ufeff][^\W\d_]+)*")
MAX_OBFUSCATION_EXAMPLES = 3


def _script(char: str) -> str:
    name = unicodedata.name(char, "")
    return name.split(" ", 1)[0] if name else ""


def find_disguised_words(text: str) -> list[str]:
    """Words mixing Latin and Cyrillic letters, or with invisible characters inside them."""
    found: list[str] = []
    for match in _WORD.finditer(text):
        word = match.group(0)
        scripts = {_script(c) for c in word if c.isalpha()}
        if ({"LATIN", "CYRILLIC"} <= scripts) or _HIDDEN_INSIDE_WORD.search(word):
            shown = "".join(f"[U+{ord(c):04X}]" if not c.isprintable() or _script(c) == "CYRILLIC"
                            else c for c in word)  # fmt: skip
            if shown not in found:
                found.append(shown)
        if len(found) >= MAX_OBFUSCATION_EXAMPLES:
            break
    return found


class ContentAnalyzer:
    name = "content"

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        return aggregate(
            self.name,
            [
                *self._ai_instructions(email),
                *self._recipient_in_subject(email),
                *self._disguised(email),
            ],
            "passages",
        )

    @staticmethod
    def _recipient_in_subject(email: ParsedEmail) -> list[Finding]:
        subject = email.subject.lower()
        address = next(
            (a.address for a in email.to if a.address and a.address.lower() in subject), None
        )
        if not address:
            return []
        return [
            Finding(
                "SUBJECT_MENTIONS_RECIPIENT",
                f"The subject line includes your email address ({address}). Mass phishing does "
                "this to look personal; companies you deal with usually use your name.",
                [Evidence(kind="header", label="Subject", value=email.subject)],
            )
        ]

    @staticmethod
    def _disguised(email: ParsedEmail) -> list[Finding]:
        sender_name = email.from_.display_name if email.from_ else ""
        visible = "\n".join(
            [
                sender_name,
                email.subject,
                email.text_body,
                *(u.visible_text or "" for u in email.urls),
            ]
        )
        words = find_disguised_words(visible)
        if not words:
            return []
        return [
            Finding(
                "TEXT_OBFUSCATION",
                "Some words are disguised with look-alike letters from another alphabet or with "
                "invisible characters. This hides them from spam filters while looking normal to "
                "you.",
                [Evidence(kind="body", label="Disguised word", value=w) for w in words],
            )
        ]

    @staticmethod
    def _ai_instructions(email: ParsedEmail) -> list[Finding]:
        text = "\n".join([email.subject, email.text_body, email.html_body])
        return [
            Finding(
                "CONTENT_AI_INSTRUCTIONS",
                "The email contains text addressed to AI or automated security tools, often "
                "hidden, trying to get it marked as safe. Legitimate senders have no reason to "
                "do this.",
                [Evidence(kind="body", label="Hidden instruction", value=snippet)],
            )
            for snippet in find_ai_instructions(text)
        ]
