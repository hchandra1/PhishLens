import re
from pathlib import Path

from phishlens.catalog import load_catalog

SOURCE = Path(__file__).parent.parent / "src" / "phishlens"

# Upper-snake strings in analyzer code that are not signal ids.
NOT_SIGNALS = {
    # Google Safe Browsing API vocabulary
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
    "ANY_PLATFORM", "URL",
    # environment variables
    "GOOGLE_SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY",
}  # fmt: skip


def test_every_signal_id_used_in_code_is_configured():
    used = set()
    for path in (SOURCE / "analyzers").glob("*.py"):
        found = re.findall(r'"([A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)"', path.read_text())
        used |= {s for s in found if not s.startswith("PHISHLENS_")} - NOT_SIGNALS
    assert used, "no signal ids found; did the pattern break?"
    assert used - set(load_catalog()) == set()


def test_only_trust_signals_have_negative_weight():
    for signal_id, spec in load_catalog().items():
        if spec.weight < 0:
            assert spec.severity == "info", signal_id
