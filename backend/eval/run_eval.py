"""Evaluate the offline analyzers on the public corpora.

Every email is assigned to a "dev" or "test" split by a hash of its content, so the
split is stable. Rules may only be tuned by looking at dev; test is the held-out
set the headline numbers come from.

Usage:
  uv run python eval/download.py                    # once
  uv run python eval/run_eval.py --split dev        # look at mistakes while tuning
  uv run python eval/run_eval.py --split test --report eval/RESULTS.md

  # With the AI content check, on a fixed random sample (calls the Claude API; costs money):
  ANTHROPIC_API_KEY=... uv run python eval/run_eval.py --split test --with-llm --limit 100 \
      --report eval/RESULTS_LLM.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mailbox
import random
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from functools import partial
from pathlib import Path

from phishlens.analyzers import LlmContentAnalyzer, offline_analyzers
from phishlens.engine import analyze
from phishlens.parser import EmailParseError, parse_email

DATA = Path(__file__).parent / "data"


@dataclass
class Result:
    source: str
    truth: str  # "phishing" | "legitimate"
    label: str  # predicted: "safe" | "suspicious" | "phishing"
    score: float
    signals: list[str]
    subject: str
    sender: str
    offline_label: str = ""  # with --with-llm: the label without the AI check, same email
    llm_status: str = ""


def load_corpus() -> list[tuple[str, str, bytes]]:
    """(source, truth, raw bytes) for every email."""
    emails = []
    for path in sorted((DATA / "phishing").glob("*.mbox")):
        box = mailbox.mbox(path)
        for key in box.keys():  # noqa: SIM118 - iterating a mailbox yields messages, not keys
            emails.append((f"{path.stem}#{key}", "phishing", box.get_bytes(key)))
    for path in sorted((DATA / "ham").rglob("*")):
        if path.is_file() and path.name != "cmds":
            emails.append((f"{path.parent.name}/{path.name}", "legitimate", path.read_bytes()))
    if not emails:
        raise SystemExit("No data. Run: uv run python eval/download.py")
    return emails


def split_of(raw: bytes) -> str:
    return "dev" if hashlib.sha256(raw).digest()[0] % 2 == 0 else "test"


def evaluate_one(item: tuple[str, str, bytes], with_llm: bool = False) -> Result | None:
    source, truth, raw = item
    try:
        email = parse_email(raw)
    except EmailParseError:
        return None
    offline = analyze(email, offline_analyzers())
    verdict, llm_status = offline, ""
    if with_llm:
        llm = LlmContentAnalyzer(enabled=True, timeout_seconds=60)
        verdict = analyze(email, [*offline_analyzers(), llm], deadline_seconds=90)
        report = next(r for r in verdict.analyzers if r.analyzer == "llm")
        llm_status = (
            report.status.value
            if report.status.value == "ok"
            else f"{report.status.value}: {report.detail}"
        )
    return Result(
        offline_label=offline.label.value if with_llm else "",
        llm_status=llm_status,
        source=source,
        truth=truth,
        label=verdict.label.value,
        score=verdict.score,
        signals=[s.id for s in verdict.signals if s.weight > 0],
        subject=email.subject[:80],
        sender=email.from_.address if email.from_ else "",
    )


def metrics(results: list[Result]) -> dict:
    phish = [r for r in results if r.truth == "phishing"]
    legit = [r for r in results if r.truth == "legitimate"]

    def rates(flagged) -> dict:
        tp = sum(flagged(r) for r in phish)
        fp = sum(flagged(r) for r in legit)
        return {
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / len(phish) if phish else 0.0,
            "false_positive_rate": fp / len(legit) if legit else 0.0,
            "false_positives": fp,
            "missed": len(phish) - tp,
        }

    return {
        "counts": {"phishing": len(phish), "legitimate": len(legit)},
        "confusion": {
            truth: dict(Counter(r.label for r in results if r.truth == truth))
            for truth in ("phishing", "legitimate")
        },
        # "Flagged" = anything not labeled safe: the user is told to be careful.
        "flagged": rates(lambda r: r.label != "safe"),
        # Strict: only the "phishing" label counts.
        "phishing_label": rates(lambda r: r.label == "phishing"),
    }


def signal_rates(results: list[Result]) -> list[tuple[str, float, float]]:
    """(signal, share of phishing it fires on, share of legitimate it fires on)."""
    by_truth = {t: [r for r in results if r.truth == t] for t in ("phishing", "legitimate")}
    counts = {t: Counter(s for r in rs for s in set(r.signals)) for t, rs in by_truth.items()}
    ids = set(counts["phishing"]) | set(counts["legitimate"])
    rows = [
        (
            i,
            counts["phishing"][i] / max(1, len(by_truth["phishing"])),
            counts["legitimate"][i] / max(1, len(by_truth["legitimate"])),
        )
        for i in ids
    ]
    return sorted(rows, key=lambda row: -(row[1] + row[2]))


def print_summary(split: str, results: list[Result], skipped: int) -> None:
    m = metrics(results)
    counts = m["counts"]
    print(f"\n=== {split}: {counts['phishing']} phishing, {counts['legitimate']} legitimate "
          f"({skipped} unparseable skipped)")  # fmt: skip
    print("confusion (truth -> predicted):", json.dumps(m["confusion"]))
    for name in ("flagged", "phishing_label"):
        r = m[name]
        print(f"{name:15} FPR {r['false_positive_rate']:6.2%}  precision {r['precision']:6.2%}  "
              f"recall {r['recall']:6.2%}  "
              f"(FP {r['false_positives']}, missed {r['missed']})")  # fmt: skip
    print("\nsignal                          phishing  legitimate")
    for signal, on_phish, on_legit in signal_rates(results):
        print(f"{signal:30} {on_phish:8.1%} {on_legit:10.1%}")


def llm_comparison(results: list[Result]) -> list[str]:
    """Markdown rows: the same emails scored without and with the AI content check."""
    without = metrics([Result(**{**asdict(r), "label": r.offline_label}) for r in results])
    with_llm = metrics(results)
    failed = Counter(r.llm_status for r in results if r.llm_status != "ok")
    rows = ["| Checks | FPR (flagged) | Precision | Recall (flagged) | Recall (phishing label) |",
            "|---|---|---|---|---|"]  # fmt: skip
    for name, m in (("Offline only", without), ("Offline + AI content check", with_llm)):
        f, p = m["flagged"], m["phishing_label"]
        rows.append(f"| {name} | {f['false_positive_rate']:.1%} | {f['precision']:.1%} | "
                    f"{f['recall']:.1%} | {p['recall']:.1%} |")  # fmt: skip
    rows.append("")
    rows.append(f"AI check did not run on {sum(failed.values())} emails: {dict(failed) or 'none'}.")
    return rows


def print_llm_comparison(results: list[Result]) -> None:
    print("\n" + "\n".join(llm_comparison(results)))


def write_report(path: Path, split: str, results: list[Result], skipped: int) -> None:
    m = metrics(results)
    lines = [
        f"<!-- Generated by eval/run_eval.py --split {split}. Do not edit by hand. -->",
        f"## Results on the held-out {split} split",
        "",
        f"{m['counts']['phishing']} phishing and {m['counts']['legitimate']} legitimate emails "
        f"({skipped} unparseable skipped). "
        + (
            "Offline analyzers plus the AI content check (no reputation lookups)."
            if results and results[0].llm_status
            else "Offline analyzers only (no LLM, no reputation lookups)."
        ),  # fmt: skip
        "",
        *(
            [
                "**Same emails, without and with the AI content check**",
                "",
                *llm_comparison(results),
                "",
            ]
            if results and results[0].llm_status
            else []
        ),  # fmt: skip
        "| Threshold | False positive rate | Precision | Recall | False positives | Missed phish |",
        "|---|---|---|---|---|---|",
    ]
    for name, title in (("flagged", "Flagged (suspicious or phishing)"),
                        ("phishing_label", "Labeled phishing")):  # fmt: skip
        r = m[name]
        lines.append(
            f"| {title} | **{r['false_positive_rate']:.1%}** | {r['precision']:.1%} | "
            f"{r['recall']:.1%} | {r['false_positives']} | {r['missed']} |"
        )
    lines += ["", "**Predicted label by true class**", "",
              "| True class | safe | suspicious | phishing |", "|---|---|---|---|"]  # fmt: skip
    for truth in ("phishing", "legitimate"):
        c = m["confusion"][truth]
        lines.append(
            f"| {truth} | {c.get('safe', 0)} | {c.get('suspicious', 0)} | {c.get('phishing', 0)} |"
        )  # noqa: E501
    lines += ["", "**How often each signal fires**", "", "| Signal | on phishing | on legitimate |",
              "|---|---|---|"]  # fmt: skip
    for signal, p, legit in signal_rates(results):
        lines.append(f"| `{signal}` | {p:.1%} | {legit:.1%} |")

    false_pos = sorted((r for r in results if r.truth == "legitimate" and r.label != "safe"),
                       key=lambda r: -r.score)  # fmt: skip
    missed = [r for r in results if r.truth == "phishing" and r.label == "safe"]
    lines += ["", f"**Legitimate emails flagged ({len(false_pos)}), highest score first**", ""]
    lines += _table(false_pos[:25])
    lines += ["", f"**Phishing labeled safe ({len(missed)}), first 25**", ""]
    lines += _table(missed[:25])
    path.write_text("\n".join(lines) + "\n")
    print(f"wrote {path}")


def _table(rows: list[Result]) -> list[str]:
    if not rows:
        return ["None."]
    out = ["| Source | Subject | Label | Score | Signals |", "|---|---|---|---|---|"]
    for r in rows:
        subject = r.subject.replace("|", "\\|") or "(none)"
        out.append(
            f"| {r.source} | {subject} | {r.label} | {r.score:g} | {', '.join(r.signals) or '-'} |"
        )  # noqa: E501
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    parser.add_argument("--report", type=Path, help="write a Markdown report to this path")
    parser.add_argument("--dump", type=Path, help="write every result as JSON lines")
    parser.add_argument("--with-llm", action="store_true", help="add the AI content check")
    parser.add_argument("--limit", type=int, help="random sample of at most N emails per class")
    parser.add_argument("--yes", action="store_true", help="skip the cost confirmation")
    args = parser.parse_args()

    corpus = [e for e in load_corpus() if args.split == "all" or split_of(e[2]) == args.split]
    if args.limit:
        rng = random.Random(0)  # same sample every run, so results are comparable
        by_class = {t: [e for e in corpus if e[1] == t] for t in ("phishing", "legitimate")}
        corpus = [
            e for group in by_class.values() for e in rng.sample(group, min(args.limit, len(group)))
        ]
    if args.with_llm:
        print(f"This sends {len(corpus)} emails to the Claude API (one request each).")
        if not args.yes and (not sys.stdin.isatty() or input("Continue? [y/N] ").lower() != "y"):
            raise SystemExit("Cancelled. Pass --yes to skip this question.")
        # Network-bound: threads, with modest concurrency to stay under rate limits.
        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(partial(evaluate_one, with_llm=True), corpus))
    else:
        with ProcessPoolExecutor() as pool:
            outcomes = list(pool.map(evaluate_one, corpus, chunksize=32))
    results = [r for r in outcomes if r is not None]
    skipped = len(outcomes) - len(results)

    print_summary(args.split, results, skipped)
    if args.with_llm:
        print_llm_comparison(results)
    if args.dump:
        args.dump.write_text("\n".join(json.dumps(asdict(r)) for r in results) + "\n")
    if args.report:
        write_report(args.report, args.split, results, skipped)


if __name__ == "__main__":
    main()
