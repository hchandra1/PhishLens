"""Download the public evaluation corpora into eval/data/ (git-ignored).

Phishing: Jose Nazario's phishing corpus, recent years (CC BY 4.0,
          https://monkey.org/~jose/phishing/).
Legitimate: SpamAssassin public corpus "easy_ham" and "hard_ham" sets
          (https://spamassassin.apache.org/old/publiccorpus/). hard_ham is commercial
          HTML mail that looks spam-like: the hardest test for false positives.

Usage: uv run python eval/download.py
"""

from __future__ import annotations

import tarfile
from pathlib import Path

import httpx2

DATA = Path(__file__).parent / "data"
NAZARIO = "https://monkey.org/~jose/phishing/"
SPAMASSASSIN = "https://spamassassin.apache.org/old/publiccorpus/"
PHISHING_YEARS = ["phishing-2023", "phishing-2024", "phishing-2025"]
HAM_SETS = ["20030228_easy_ham.tar.bz2", "20030228_hard_ham.tar.bz2"]


def fetch(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"already have {dest.name}")
        return
    print(f"downloading {url}")
    with httpx2.stream("GET", url, timeout=120, follow_redirects=True) as response:
        response.raise_for_status()
        tmp = dest.with_suffix(".part")
        with tmp.open("wb") as out:
            for chunk in response.iter_bytes():
                out.write(chunk)
        tmp.rename(dest)


def main() -> None:
    (DATA / "phishing").mkdir(parents=True, exist_ok=True)
    (DATA / "ham").mkdir(parents=True, exist_ok=True)
    for name in PHISHING_YEARS:
        fetch(NAZARIO + name, DATA / "phishing" / f"{name}.mbox")
    for name in HAM_SETS:
        archive = DATA / name
        fetch(SPAMASSASSIN + name, archive)
        target = DATA / "ham" / name.split(".")[0]
        if not target.exists():
            with tarfile.open(archive) as tar:
                tar.extractall(target, filter="data")
    print("done")


if __name__ == "__main__":
    main()
