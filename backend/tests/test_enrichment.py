import json
import threading
from datetime import UTC, datetime, timedelta

import httpx2
import pytest
from helpers import ids, make_email

from phishlens.analyzers import offline_analyzers
from phishlens.analyzers._network import TTLCache, run_lookups
from phishlens.analyzers.domain_age import DomainAgeAnalyzer, candidate_domains, registration_date
from phishlens.analyzers.safe_browsing import SafeBrowsingAnalyzer, lookup_url
from phishlens.analyzers.virustotal import VirusTotalAnalyzer
from phishlens.engine import analyze
from phishlens.models import AnalyzerUnavailable, Attachment, Label

NOW = datetime(2026, 9, 30, tzinfo=UTC)
SHA_A, SHA_B = "a" * 64, "b" * 64


class Recorder:
    """httpx2 MockTransport handler that records requests and answers from a routing function."""

    def __init__(self, route):
        self.route, self.requests = route, []

    def __call__(self, request):
        self.requests.append(request)
        return self.route(request)

    def client(self):
        return httpx2.Client(transport=httpx2.MockTransport(self), timeout=2)


def rdap(days_old):
    date = (NOW - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"events": [{"eventAction": "last changed", "eventDate": "2026-09-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": date}]}  # fmt: skip


# --- Shared plumbing ------------------------------------------------------------------


def test_cache_expires_and_evicts_least_recent():
    now = [0.0]
    cache = TTLCache(ttl_seconds=10, max_items=2, clock=lambda: now[0])
    cache.set("a", 1)
    cache.set("b", None)  # negative results are cacheable
    assert cache.get("b", "missing") is None
    cache.get("a")
    cache.set("c", 3)  # evicts b, the least recently used
    assert cache.get("b", "missing") == "missing"
    now[0] = 11
    assert cache.get("a", "missing") == "missing"


def test_cache_does_not_store_errors():
    cache, calls = TTLCache(60), []

    def boom():
        calls.append(1)
        raise RuntimeError

    for _ in range(2):
        with pytest.raises(RuntimeError):
            cache.cached("k", boom)
    assert len(calls) == 2


def test_run_lookups_reports_slow_lookups_as_timeouts():
    release = threading.Event()
    try:
        results = run_lookups(
            ["fast", "slow"], lambda k: release.wait(5) if k == "slow" else k, 0.2
        )
    finally:
        release.set()
    assert results["fast"] == "fast"
    assert isinstance(results["slow"], TimeoutError)


# --- Domain age (RDAP) ---------------------------------------------------------------


def domain_age(route, **kwargs):
    recorder = Recorder(route)
    analyzer = DomainAgeAnalyzer(
        client=recorder.client(), enabled=True, now=lambda: NOW, cache=TTLCache(60), **kwargs
    )
    return analyzer, recorder


def test_domain_age_is_opt_in():
    with pytest.raises(AnalyzerUnavailable, match="PHISHLENS_RDAP"):
        DomainAgeAnalyzer().analyze(make_email())


def test_candidate_domains_sender_first_skipping_known_and_own():
    email = make_email(
        sender="Billing <ar@billing.new-vendor.com>",
        urls=[
            ("https://portal.new-vendor.com/pay", None),  # same registered domain as sender
            ("https://www.paypal.com/", None),  # real brand
            ("http://203.0.113.5/x", None),  # IP address
            ("https://intranet.acme-defense.com/", None),  # recipient's own organization
            ("https://fresh-site.xyz/login", None),
        ],
    )
    assert candidate_domains(email) == {"new-vendor.com": "sender", "fresh-site.xyz": "link"}


@pytest.mark.parametrize(
    ("days_old", "expected"),
    [(3, ["DOMAIN_NEWLY_REGISTERED"]), (45, ["DOMAIN_RECENTLY_REGISTERED"]), (400, [])],
)
def test_domain_age_thresholds(days_old, expected):
    analyzer, _ = domain_age(lambda r: httpx2.Response(200, json=rdap(days_old)))
    signals = analyzer.analyze(make_email(sender="A <a@new-vendor.com>"))
    assert ids(signals) == expected
    if expected:
        assert f"only {days_old} days ago" in signals[0].explanation
        assert signals[0].evidence[1].value == (NOW - timedelta(days=days_old)).date().isoformat()


def test_rdap_query_sends_only_the_domain():
    analyzer, recorder = domain_age(lambda r: httpx2.Response(200, json=rdap(400)))
    analyzer.analyze(make_email(sender="A <a@mail.new-vendor.com>"))
    (request,) = recorder.requests
    assert str(request.url) == "https://rdap.org/domain/new-vendor.com"


def test_unknown_to_rdap_is_not_suspicious():
    analyzer, _ = domain_age(lambda r: httpx2.Response(404))
    assert analyzer.analyze(make_email(sender="A <a@new-vendor.com>")) == []


def test_one_failed_lookup_does_not_hide_the_others():
    def route(request):
        if "broken" in request.url.path:
            return httpx2.Response(503)
        return httpx2.Response(200, json=rdap(2))

    analyzer, _ = domain_age(route)
    email = make_email(sender="A <a@broken-registry.com>", urls=[("https://fresh-site.xyz/", None)])
    assert ids(analyzer.analyze(email)) == ["DOMAIN_NEWLY_REGISTERED"]


def test_all_lookups_failing_is_reported_as_unavailable():
    analyzer, _ = domain_age(lambda r: httpx2.Response(503))
    with pytest.raises(AnalyzerUnavailable, match="HTTP 503"):
        analyzer.analyze(make_email(sender="A <a@new-vendor.com>"))


def test_results_are_cached_across_emails():
    analyzer, recorder = domain_age(lambda r: httpx2.Response(200, json=rdap(400)))
    for _ in range(3):
        analyzer.analyze(make_email(sender="A <a@new-vendor.com>"))
    assert len(recorder.requests) == 1


def test_registration_date_formats():
    assert registration_date({"events": []}) is None
    parsed = registration_date(
        {"events": [{"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"}]}
    )  # noqa: E501
    assert parsed == datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)


# --- Google Safe Browsing -------------------------------------------------------------


def safe_browsing(route):
    recorder = Recorder(route)
    analyzer = SafeBrowsingAnalyzer(client=recorder.client(), api_key="SECRET", cache=TTLCache(60))
    return analyzer, recorder


def listed(*urls, threat="SOCIAL_ENGINEERING"):
    return lambda r: httpx2.Response(
        200, json={"matches": [{"threatType": threat, "threat": {"url": u}} for u in urls]}
    )


def test_safe_browsing_needs_a_key():
    with pytest.raises(AnalyzerUnavailable, match="GOOGLE_SAFE_BROWSING_API_KEY"):
        SafeBrowsingAnalyzer().analyze(make_email())


def test_lookup_url_strips_personal_data():
    assert (
        lookup_url("https://Evil.example/login?email=pat@acme-defense.com#token")
        == "https://evil.example/login"
    )  # noqa: E501
    assert lookup_url("https://paypal.com@evil.example/") == "https://evil.example/"
    assert lookup_url("www.evil.example") == "http://www.evil.example/"
    assert lookup_url("mailto:x@y.com") is None


def test_listed_link_is_flagged_and_forces_phishing():
    analyzer, recorder = safe_browsing(listed("https://evil.example/login"))
    email = make_email(
        auth="mx; dmarc=pass header.from=vendor-example.com",
        urls=[("https://evil.example/login?u=pat", "View invoice"), ("https://ok.example/", None)],
    )
    (signal,) = analyzer.analyze(email)
    assert signal.id == "URL_THREAT_FEED"
    assert "phishing or scam site" in signal.explanation
    assert signal.evidence[0].value == "https://evil.example/login?u=pat"  # shown as in the email

    sent = json.loads(recorder.requests[0].content)["threatInfo"]["threatEntries"]
    assert sent == [{"url": "https://evil.example/login"}, {"url": "https://ok.example/"}]

    verdict = analyze(email, [*offline_analyzers(), analyzer])
    assert verdict.label == Label.PHISHING
    assert "Google's list of dangerous sites" in verdict.summary


def test_threat_feed_override_applies_even_when_weights_are_tuned_down():
    from phishlens.catalog import make_signal
    from phishlens.scoring import score_signals

    low = make_signal("safe_browsing", "URL_THREAT_FEED", "x", []).model_copy(update={"weight": 5})
    result = score_signals([low])
    assert result.label == Label.PHISHING
    assert "Safe Browsing" in result.override


def test_safe_browsing_caches_clean_and_listed_results():
    analyzer, recorder = safe_browsing(listed())
    email = make_email(urls=[("https://ok.example/", None)])
    analyzer.analyze(email)
    analyzer.analyze(email)
    assert len(recorder.requests) == 1


def test_safe_browsing_errors_never_leak_the_api_key():
    analyzer, _ = safe_browsing(lambda r: httpx2.Response(403))
    with pytest.raises(AnalyzerUnavailable) as caught:
        analyzer.analyze(make_email(urls=[("https://x.example/", None)]))
    assert "rejected the API key" in str(caught.value)
    assert "SECRET" not in str(caught.value)


def test_safe_browsing_bad_response():
    analyzer, _ = safe_browsing(lambda r: httpx2.Response(200, json={"matches": [{"oops": 1}]}))
    with pytest.raises(AnalyzerUnavailable, match="unexpected response"):
        analyzer.analyze(make_email(urls=[("https://x.example/", None)]))


def test_no_links_means_no_request():
    analyzer, recorder = safe_browsing(listed())
    assert analyzer.analyze(make_email()) == []
    assert recorder.requests == []


# --- VirusTotal -------------------------------------------------------------------------


def virustotal(route):
    recorder = Recorder(route)
    analyzer = VirusTotalAnalyzer(client=recorder.client(), api_key="VTKEY", cache=TTLCache(60))
    return analyzer, recorder


def vt_stats(malicious, total=70):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": 0, "undetected": total - malicious}}}}  # fmt: skip


def with_files(*files):
    email = make_email()
    return email.model_copy(update={"attachments": [
        Attachment(filename=name, content_type="application/octet-stream", size=10, sha256=sha)
        for name, sha in files]})  # fmt: skip


def test_virustotal_needs_a_key():
    with pytest.raises(AnalyzerUnavailable, match="VIRUSTOTAL_API_KEY"):
        VirusTotalAnalyzer().analyze(make_email())


def test_known_malware_forces_phishing():
    analyzer, recorder = virustotal(lambda r: httpx2.Response(200, json=vt_stats(41)))
    email = with_files(("invoice.pdf", SHA_A))
    (signal,) = analyzer.analyze(email)
    assert signal.id == "ATTACHMENT_KNOWN_MALWARE"
    assert "41 of 70" in signal.explanation

    (request,) = recorder.requests
    assert request.url.path == f"/api/v3/files/{SHA_A}"  # only the hash leaves the machine
    assert request.method == "GET" and request.headers["x-apikey"] == "VTKEY"

    verdict = analyze(email, [*offline_analyzers(), analyzer])
    assert verdict.label == Label.PHISHING
    assert "identify as malware" in verdict.summary


def test_few_detections_and_unknown_files():
    def route(request):
        if SHA_A in request.url.path:
            return httpx2.Response(200, json=vt_stats(1))
        return httpx2.Response(404)

    analyzer, _ = virustotal(route)
    signals = analyzer.analyze(with_files(("a.pdf", SHA_A), ("b.pdf", SHA_B)))
    assert ids(signals) == ["ATTACHMENT_SOME_DETECTIONS"]
    assert "may be a false alarm" in signals[0].explanation


def test_rate_limited_virustotal_is_unavailable():
    analyzer, _ = virustotal(lambda r: httpx2.Response(429))
    with pytest.raises(AnalyzerUnavailable, match="rate limit"):
        analyzer.analyze(with_files(("a.pdf", SHA_A)))


def test_virustotal_lookups_are_capped_and_deduplicated():
    analyzer, recorder = virustotal(lambda r: httpx2.Response(404))
    files = [(f"f{i}.pdf", f"{i:064x}") for i in range(10)] + [("dup.pdf", f"{0:064x}")]
    analyzer.analyze(with_files(*files))
    assert len(recorder.requests) == 4
