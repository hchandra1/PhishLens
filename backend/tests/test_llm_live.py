"""Calls the real Claude API. Skipped unless PHISHLENS_LIVE_TESTS=1 and credentials exist.

PHISHLENS_LIVE_TESTS=1 ANTHROPIC_API_KEY=... uv run pytest tests/test_llm_live.py -v
"""

import os
from pathlib import Path

import pytest

from phishlens.analyzers import offline_analyzers
from phishlens.analyzers.llm import LlmContentAnalyzer
from phishlens.engine import analyze
from phishlens.models import AnalyzerStatus, Label
from phishlens.parser import parse_email

pytestmark = pytest.mark.skipif(
    os.environ.get("PHISHLENS_LIVE_TESTS") != "1",
    reason="live API test; set PHISHLENS_LIVE_TESTS=1",
)
FIXTURES = Path(__file__).parent / "fixtures"


def run(name):
    analyzers = [*offline_analyzers(), LlmContentAnalyzer(enabled=True, timeout_seconds=60)]
    verdict = analyze(parse_email((FIXTURES / name).read_bytes()), analyzers, deadline_seconds=90)
    report = next(r for r in verdict.analyzers if r.analyzer == "llm")
    assert report.status == AnalyzerStatus.OK, report.detail
    return verdict, {s.id for s in verdict.signals if s.analyzer == "llm"}


def test_prompt_injection_does_not_fool_the_model():
    verdict, llm_ids = run("10_prompt_injection.eml")
    assert verdict.label == Label.PHISHING
    assert "LLM_CREDENTIAL_REQUEST" in llm_ids
    assert llm_ids & {"LLM_AI_INSTRUCTIONS", "LLM_PRESSURE_TACTICS"}


def test_ceo_fraud_payment_request_is_recognized():
    verdict, llm_ids = run("03_encoded_headers.eml")
    assert "LLM_PAYMENT_REQUEST" in llm_ids
    assert verdict.label == Label.PHISHING


def test_ordinary_invoice_gets_no_high_severity_llm_findings():
    verdict, llm_ids = run("01_plain_text.eml")
    assert verdict.label == Label.SAFE
    assert not llm_ids & {"LLM_CREDENTIAL_REQUEST", "LLM_AI_INSTRUCTIONS"}
