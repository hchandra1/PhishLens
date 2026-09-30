import pytest


@pytest.fixture(autouse=True)
def _no_live_llm(monkeypatch):
    """Tests never call real external services unless a test opts in explicitly."""
    for name in (
        "PHISHLENS_TRUSTED_AUTHSERV_IDS",
        "PHISHLENS_LLM",
        "PHISHLENS_RDAP",
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "VIRUSTOTAL_API_KEY",
    ):  # noqa: E501
        monkeypatch.delenv(name, raising=False)
