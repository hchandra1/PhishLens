import pytest
from helpers import ids, make_email

from phishlens.analyzers.attachments import AttachmentAnalyzer

analyze = AttachmentAnalyzer().analyze


def check(*attachments):
    return ids(analyze(make_email(attachments=list(attachments))))


def test_ordinary_documents_are_clean():
    assert (
        check(
            ("Invoice 2026-09.pdf", "application/pdf"),
            ("photo.JPG", "image/jpg"),
            ("notes.csv", "text/plain"),
            (
                "Q3 Report.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            ("data.bin", "application/octet-stream"),
        )
        == []
    )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("setup.exe", "ATTACHMENT_EXECUTABLE"),
        ("update.js", "ATTACHMENT_EXECUTABLE"),
        ("Shortcut.lnk", "ATTACHMENT_EXECUTABLE"),
        ("Secure_Message.html", "ATTACHMENT_HTML"),
        ("fax.svg", "ATTACHMENT_HTML"),
        ("shipping_docs.iso", "ATTACHMENT_DISK_IMAGE"),
        ("Payroll.xlsm", "ATTACHMENT_MACRO_OFFICE"),
        ("scan.one", "ATTACHMENT_MACRO_OFFICE"),
        ("files.zip", "ATTACHMENT_ARCHIVE"),
        ("invoice.pdf.exe", "ATTACHMENT_DOUBLE_EXTENSION"),
        ("invoice.pdf   .html", "ATTACHMENT_DOUBLE_EXTENSION"),
        ("invoice.exe. ", "ATTACHMENT_EXECUTABLE"),  # Windows drops trailing dots and spaces
        ("invoice‮fdp.exe", "ATTACHMENT_RTLO_FILENAME"),
    ],
)
def test_risky_names(name, expected):
    assert check((name, "application/octet-stream")) == [expected]


def test_double_extension_replaces_the_plain_type_signal():
    assert check(("invoice.pdf.exe", "application/octet-stream")) == ["ATTACHMENT_DOUBLE_EXTENSION"]
    assert check(("backup.pdf.zip", "application/zip")) == ["ATTACHMENT_ARCHIVE"]


def test_rtlo_evidence_shows_the_hidden_character():
    (signal,) = analyze(make_email(attachments=[("invoice‮fdp.exe", "application/pdf")]))[:1]
    assert "[U+202E]" in signal.evidence[0].value
    assert "‮" not in signal.explanation


def test_declared_type_mismatch():
    assert check(("invoice.pdf", "text/html")) == ["ATTACHMENT_MIME_MISMATCH"]
    assert check(("invoice.pdf.exe", "application/pdf")) == [
        "ATTACHMENT_DOUBLE_EXTENSION",
        "ATTACHMENT_MIME_MISMATCH",
    ]
    assert check(("archive.zip", "application/x-zip-compressed")) == ["ATTACHMENT_ARCHIVE"]


def test_unnamed_inline_parts_are_ignored():
    email = make_email(attachments=[("x.png", "image/png")])
    email.attachments[0].__dict__["filename"] = None  # frozen model; simulate a nameless part
    assert analyze(email) == []
