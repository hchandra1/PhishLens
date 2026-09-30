from helpers import ids, make_email

from phishlens.analyzers.auth import AuthAnalyzer, parse_authentication_results

analyze = AuthAnalyzer().analyze

GOOD = "mx.acme.com; spf=pass smtp.mailfrom=vendor-example.com; dkim=pass header.d=vendor-example.com; dmarc=pass header.from=vendor-example.com"  # noqa: E501


def test_parse_microsoft_style_header_with_comments():
    header = parse_authentication_results(
        "spf=pass (sender IP is 203.0.113.5) smtp.mailfrom=x.com; dkim=none (message not "
        "signed) header.d=none;dmarc=fail action=none header.from=x.com;compauth=fail reason=001"
    )
    results = {r.method: r.result for r in header.results}
    assert results == {"spf": "pass", "dkim": "none", "dmarc": "fail", "compauth": "fail"}
    assert header.get("dmarc")[0].properties["header.from"] == "x.com"


def test_result_text_inside_a_property_is_not_trusted():
    # An attacker controls the envelope sender; it must not be read as a result.
    header = parse_authentication_results("mx; spf=fail smtp.mailfrom=dmarc=pass@evil.com")
    assert [r.method for r in header.results] == ["spf"]


def test_dmarc_pass_is_a_trust_signal():
    signals = analyze(make_email(auth=GOOD))
    assert ids(signals) == ["DMARC_PASS"]
    assert signals[0].weight < 0


def test_dmarc_pass_for_a_different_domain_is_not_trusted():
    auth = "mx; spf=pass smtp.mailfrom=evil.com; dmarc=pass header.from=evil.com"
    assert ids(analyze(make_email(auth=auth))) == []


def test_dmarc_fail_is_scored_once_with_spf_and_dkim_as_evidence():
    auth = "mx; spf=fail smtp.mailfrom=evil.com; dkim=fail header.d=evil.com; dmarc=fail header.from=vendor-example.com"  # noqa: E501
    (signal,) = analyze(make_email(auth=auth))
    assert signal.id == "DMARC_FAIL"
    assert {e.label for e in signal.evidence} >= {"SPF", "DKIM", "DMARC"}
    assert "vendor-example.com" in signal.explanation


def test_without_dmarc_verdict_spf_and_dkim_are_scored():
    auth = "mx; spf=softfail smtp.mailfrom=x@evil.com; dkim=fail header.d=evil.com; dmarc=none"
    assert ids(analyze(make_email(auth=auth))) == ["SPF_SOFTFAIL", "DKIM_FAIL"]
    auth = "mx; spf=fail smtp.mailfrom=evil.com; dmarc=temperror"
    assert ids(analyze(make_email(auth=auth))) == ["SPF_FAIL"]


def test_one_passing_dkim_signature_is_enough():
    auth = "mx; dkim=fail header.d=list.example; dkim=pass header.d=vendor-example.com"
    assert ids(analyze(make_email(auth=auth))) == []


def test_missing_header():
    assert ids(analyze(make_email(auth=None))) == ["AUTH_RESULTS_MISSING"]


def test_forged_lower_header_is_ignored():
    # The attacker adds a passing header; the receiving server prepends the real one above it.
    real = "mx.acme.com; spf=fail smtp.mailfrom=evil.com; dmarc=fail header.from=vendor-example.com"
    assert ids(analyze(make_email(auth=[real, GOOD]))) == ["DMARC_FAIL"]


def test_trusted_authserv_ids_from_environment(monkeypatch):
    monkeypatch.setenv("PHISHLENS_TRUSTED_AUTHSERV_IDS", "mx.acme.com, mx2.acme.com")
    assert AuthAnalyzer().trusted_authserv_ids == ["mx.acme.com", "mx2.acme.com"]


def test_trusted_authserv_id_selects_our_servers_header():
    forged = GOOD.replace("mx.acme.com", "mx.evil.com")
    analyzer = AuthAnalyzer(trusted_authserv_ids=["mx.acme.com"])
    assert ids(analyzer.analyze(make_email(auth=[forged]))) == ["AUTH_RESULTS_MISSING"]
    assert ids(analyzer.analyze(make_email(auth=[forged, GOOD]))) == ["DMARC_PASS"]
