"""Attachment names and declared types. Files are never opened or executed."""

from __future__ import annotations

import mimetypes

from phishlens.analyzers._common import Finding, aggregate
from phishlens.knowledge import (
    ARCHIVE_EXTENSIONS,
    DISK_IMAGE_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    HTML_EXTENSIONS,
    MACRO_OFFICE_EXTENSIONS,
)
from phishlens.models import Attachment, Evidence, ParsedEmail, Signal

# Invisible characters that reorder how text is displayed: "invoice‮fdp.exe"
# is shown as "invoiceexe.pdf".
_BIDI_CONTROLS = set("‪‫‬‭‮⁦⁧⁨⁩‎‏")

_GENERIC_TYPES = {"application/octet-stream", "binary/octet-stream", "application/x-download",
                  "application/force-download", "application/unknown", ""}  # fmt: skip
_EXECUTABLE_TYPE = "application/x-msdownload"
_TYPE_ALIASES = {
    "image/jpg": "image/jpeg",
    "image/pjpeg": "image/jpeg",
    "application/x-zip-compressed": "application/zip",
    "application/x-zip": "application/zip",
    "application/x-pdf": "application/pdf",
    "text/xml": "application/xml",
    "application/x-dosexec": _EXECUTABLE_TYPE,
    "application/x-msdos-program": _EXECUTABLE_TYPE,
    "application/x-executable": _EXECUTABLE_TYPE,
    "application/exe": _EXECUTABLE_TYPE,
    "application/vnd.microsoft.portable-executable": _EXECUTABLE_TYPE,
}
# Python's built-in table (deliberately not the OS's, so results don't vary by machine),
# plus types it lacks.
_MIME = mimetypes.MimeTypes()
for _ext, _type in {
    ".exe": _EXECUTABLE_TYPE,
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}.items():
    _MIME.add_type(_type, _ext)

_KIND_EXPLANATIONS = {
    "ATTACHMENT_EXECUTABLE": "is a program; opening it would run code on your computer.",
    "ATTACHMENT_HTML": "is a web page file. Attached web pages are often fake login screens "
    "that run outside your browser's protections.",
    "ATTACHMENT_DISK_IMAGE": "is a disk image, a file type often used to sneak malware past "
    "security warnings.",
    "ATTACHMENT_MACRO_OFFICE": "is an Office file that can contain macros, small programs that "
    'run if you click "Enable content".',
    "ATTACHMENT_ARCHIVE": "is a compressed archive, which can hide dangerous files from email "
    "scanners.",
}
_KIND_BY_EXTENSION = [
    (EXECUTABLE_EXTENSIONS, "ATTACHMENT_EXECUTABLE"),
    (HTML_EXTENSIONS, "ATTACHMENT_HTML"),
    (DISK_IMAGE_EXTENSIONS, "ATTACHMENT_DISK_IMAGE"),
    (MACRO_OFFICE_EXTENSIONS, "ATTACHMENT_MACRO_OFFICE"),
    (ARCHIVE_EXTENSIONS, "ATTACHMENT_ARCHIVE"),
]


def _normalize_type(content_type: str) -> str:
    content_type = content_type.lower().strip()
    return _TYPE_ALIASES.get(content_type, content_type)


class AttachmentAnalyzer:
    name = "attachments"

    def analyze(self, email: ParsedEmail) -> list[Signal]:
        findings = [f for a in email.attachments for f in self._check(a)]
        return aggregate(self.name, findings, "attachments")

    def _check(self, attachment: Attachment) -> list[Finding]:
        raw_name = attachment.filename
        if not raw_name:
            return []
        evidence = [Evidence(kind="attachment", label="File", value=_printable(raw_name))]
        # Windows ignores trailing dots and spaces: "invoice.exe. " opens as invoice.exe.
        name = "".join(c for c in raw_name if c not in _BIDI_CONTROLS).lower().rstrip(". ")
        parts = [p.strip() for p in name.split(".")]
        extension = parts[-1] if len(parts) > 1 else ""
        kind = next((k for exts, k in _KIND_BY_EXTENSION if extension in exts), None)
        findings: list[Finding] = []

        if any(c in _BIDI_CONTROLS for c in raw_name):
            findings.append(
                Finding(
                    "ATTACHMENT_RTLO_FILENAME",
                    f'The file name "{_printable(raw_name)}" hides its real type with an '
                    f"invisible text-reversing character. It is really a .{extension} file.",
                    evidence,
                )
            )
        elif (
            kind not in (None, "ATTACHMENT_ARCHIVE")
            and len(parts) >= 3
            and parts[-2] in DOCUMENT_EXTENSIONS
        ):
            findings.append(
                Finding(
                    "ATTACHMENT_DOUBLE_EXTENSION",
                    f'"{raw_name}" is made to look like a .{parts[-2]} file, but it is really '
                    f"a .{extension} file.",
                    evidence,
                )
            )
        elif kind:
            findings.append(Finding(kind, f'"{raw_name}" {_KIND_EXPLANATIONS[kind]}', evidence))

        findings += self._type_mismatch(attachment, name, raw_name, evidence)
        return findings

    @staticmethod
    def _type_mismatch(
        attachment: Attachment, name: str, raw_name: str, evidence: list[Evidence]
    ) -> list[Finding]:
        declared = _normalize_type(attachment.content_type)
        expected = _normalize_type(_MIME.guess_type(name, strict=False)[0] or "")
        if declared in _GENERIC_TYPES or expected in _GENERIC_TYPES or declared == expected:
            return []
        if declared.startswith("text/") and expected.startswith("text/"):
            return []  # text/plain for a .csv is normal
        return [
            Finding(
                "ATTACHMENT_MIME_MISMATCH",
                f'"{_printable(raw_name)}" is labeled as {declared}, but its name says it is '
                f"{expected}. A mismatch like this can be used to slip past filters.",
                [*evidence, Evidence(kind="attachment", label="Labeled as", value=declared)],
            )
        ]


def _printable(name: str) -> str:
    """Show invisible control characters instead of letting them reorder the text."""
    return "".join(f"[U+{ord(c):04X}]" if c in _BIDI_CONTROLS else c for c in name)
