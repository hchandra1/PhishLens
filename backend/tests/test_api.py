import logging
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from phishlens import api
from phishlens.analyzers import default_analyzers
from phishlens.api import Settings, create_app
from phishlens.ratelimit import RateLimiter, parse_rate

FIXTURES = Path(__file__).parent / "fixtures"
PHISH = (FIXTURES / "02_multipart_alternative.eml").read_bytes()
LEGIT = (FIXTURES / "01_plain_text.eml").read_bytes()
EML = {"Content-Type": "message/rfc822"}


def make_client(**settings) -> TestClient:
    return TestClient(create_app(default_analyzers(), Settings(**settings)))


@pytest.fixture
def client():
    with make_client() as test_client:
        yield test_client


# --- Health --------------------------------------------------------------------------------


def test_health_reports_optional_checks_without_secrets(client):
    assert client.get("/api/health").json() == {
        "status": "ok",
        "optional_checks": {
            "llm": False, "domain_age": False, "safe_browsing": False, "virustotal": False,
        },
        "access_code_required": False,
    }  # fmt: skip


def test_health_shows_configured_check(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "secret-key")
    with make_client(access_code="hunter2") as client:
        body = client.get("/api/health").text
    assert '"virustotal":true' in body and '"access_code_required":true' in body
    assert "secret-key" not in body and "hunter2" not in body


# --- Analyze -------------------------------------------------------------------------------


def test_analyze_raw_eml(client):
    response = client.post("/api/analyze", content=PHISH, headers=EML)
    assert response.status_code == 200
    verdict = response.json()
    assert verdict["label"] == "phishing"
    assert verdict["email"]["subject"] == "Action required: mailbox storage"
    mismatch = next(s for s in verdict["signals"] if s["id"] == "LINK_TEXT_MISMATCH")
    assert [e["label"] for e in mismatch["evidence"]] == ["Link text", "Actually goes to"]
    assert {r["analyzer"] for r in verdict["analyzers"]} >= {"auth", "urls", "llm"}


def test_analyze_json_paste(client):
    response = client.post("/api/analyze", json={"raw": LEGIT.decode()})
    assert response.status_code == 200
    assert response.json()["label"] == "safe"


def test_body_only_paste_returns_a_verdict_with_a_hint(client):
    response = client.post("/api/analyze", json={"raw": "Hi, please buy gift cards today."})
    assert response.status_code == 200
    assert any("Show original" in w for w in response.json()["email"]["warnings"])


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"json": {"raw": ""}}, 400),  # empty email
        ({"json": {"email": "x"}}, 422),  # wrong field
        ({"json": ["x"]}, 422),
        ({"content": b"{not json", "headers": {"Content-Type": "application/json"}}, 422),
        ({"content": b"x", "headers": {"Content-Type": "image/png"}}, 415),
        ({"files": {"file": ("a.eml", LEGIT)}}, 415),  # multipart is not accepted
    ],
)
def test_bad_requests(client, kwargs, status):
    response = client.post("/api/analyze", **kwargs)
    assert response.status_code == status
    assert response.json()["detail"]


def test_oversized_body_is_rejected(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_BODY_BYTES", 1000)
    response = client.post("/api/analyze", content=b"Subject: x\n\n" + b"a" * 2000, headers=EML)
    assert response.status_code == 413


def test_oversized_body_without_content_length_is_rejected(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_BODY_BYTES", 1000)

    def chunks():
        for _ in range(5):
            yield b"a" * 500

    response = client.post("/api/analyze", content=chunks(), headers=EML)
    assert response.status_code == 413


def test_email_content_is_never_logged(client, caplog):
    caplog.set_level(logging.DEBUG)
    client.post("/api/analyze", content=PHISH, headers=EML)
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "label=phishing" in logged
    assert "mailbox storage" not in logged
    assert "login-verify" not in logged


# --- Abuse controls ------------------------------------------------------------------------


def test_access_code():
    with make_client(access_code="s3cret") as client:
        assert client.post("/api/analyze", content=LEGIT, headers=EML).status_code == 401
        wrong = {**EML, "X-Access-Code": "guess"}
        assert client.post("/api/analyze", content=LEGIT, headers=wrong).status_code == 401
        right = {**EML, "X-Access-Code": "s3cret"}
        assert client.post("/api/analyze", content=LEGIT, headers=right).status_code == 200


def test_rate_limit_applies_to_wrong_access_codes_too():
    with make_client(access_code="s3cret", rate_limit="3/minute") as client:
        wrong = {**EML, "X-Access-Code": "guess"}
        statuses = [
            client.post("/api/analyze", content=LEGIT, headers=wrong).status_code for _ in range(4)
        ]
    assert statuses == [401, 401, 401, 429]


def test_rate_limit_sets_retry_after():
    with make_client(rate_limit="2/minute") as client:
        for _ in range(2):
            assert client.post("/api/analyze", content=LEGIT, headers=EML).status_code == 200
        response = client.post("/api/analyze", content=LEGIT, headers=EML)
    assert response.status_code == 429
    assert 0 < int(response.headers["retry-after"]) <= 60


def test_spoofed_forwarded_for_does_not_escape_the_limit():
    with make_client(rate_limit="2/minute", proxy_hops=1) as client:
        statuses = [
            client.post(
                "/api/analyze",
                content=LEGIT,
                # The client controls the left part; the proxy appends the real address.
                headers={**EML, "X-Forwarded-For": f"10.0.0.{i}, 203.0.113.7"},
            ).status_code
            for i in range(3)
        ]
    assert statuses == [200, 200, 429]


def test_rate_limiter_window_and_eviction():
    now = [0.0]
    limiter = RateLimiter(limit=2, window_seconds=10, max_clients=2, clock=lambda: now[0])
    assert limiter.check("a") is None and limiter.check("a") is None
    assert limiter.check("a") == 10
    now[0] = 10.5
    assert limiter.check("a") is None  # the window slid
    limiter.check("b")
    limiter.check("c")  # evicts the least recently seen client
    assert "a" not in limiter._hits
    assert parse_rate("30/minute") == (30, 60.0) and parse_rate("5/second") == (5, 1.0)


# --- UI, manifest and headers ----------------------------------------------------------------


def test_serves_static_ui_and_keeps_api_paths(tmp_path):
    (tmp_path / "index.html").write_text("<h1>PhishLens UI</h1>")
    (tmp_path / "outlook").mkdir()
    (tmp_path / "outlook" / "index.html").write_text("<h1>Add-in</h1>")
    with make_client(static_dir=tmp_path) as client:
        home = client.get("/")
        assert "PhishLens UI" in home.text
        assert home.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in home.headers["content-security-policy"]

        addin = client.get("/outlook/")
        assert "Add-in" in addin.text
        assert "x-frame-options" not in addin.headers  # Outlook shows it in a frame
        assert "appsforoffice.microsoft.com" in addin.headers["content-security-policy"]

        assert client.get("/api/health").json()["status"] == "ok"
        assert client.get("/api/nope").status_code == 404
        assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_outlook_manifest_uses_public_url():
    with make_client(public_url="https://phishlens.example.com") as client:
        response = client.get("/outlook/manifest.xml")
    assert response.headers["content-type"].startswith("application/xml")
    assert "BASE_URL" not in response.text
    assert "https://phishlens.example.com/outlook/" in response.text
    ET.fromstring(response.content)  # well-formed XML


def test_outlook_manifest_derives_https_url_behind_a_proxy():
    with make_client(proxy_hops=1) as client:
        response = client.get("/outlook/manifest.xml", headers={"X-Forwarded-Proto": "https"})
    assert "https://testserver/outlook/" in response.text
