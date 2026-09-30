# Evaluation

How well do the offline checks separate phishing from legitimate mail, and above all,
how often do they wrongly flag real mail? A tool that cries wolf on vendor invoices
gets ignored, so the **false positive rate is the headline metric**.

## Method

| | Source | Emails |
|---|---|---|
| Phishing | [Jose Nazario's phishing corpus](https://monkey.org/~jose/phishing/), 2023–2025 mailboxes (CC BY 4.0) | 1,303 |
| Legitimate | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) `easy_ham` + `hard_ham` (2002–2003) | 2,750 |

- Each email goes to a **dev** or **test** split by a hash of its bytes (about 50/50, stable).
- Rules were only changed after studying **dev**. The **test** split was run twice: once
  before any tuning (headline numbers only, no examples viewed) and once after the rules
  were frozen. Every rule added from dev evidence is a known phishing technique, has unit
  tests including the false-positive cases it must avoid (`tests/test_eval_rules.py`), and
  is not keyed to this corpus.
- Only the **offline** analyzers are evaluated (see Limitations for why).
- "Flagged" means the verdict was *suspicious* or *phishing*: in both cases the user is told
  not to click and to verify. "Phishing label" counts only the stronger verdict.

Reproduce:

```bash
uv run python eval/download.py
uv run python eval/run_eval.py --split test --report eval/RESULTS.md
```

## Results (held-out test split: 640 phishing, 1,404 legitimate)

| | False positive rate | Precision | Recall | Legit wrongly labeled *phishing* |
|---|---|---|---|---|
| **Flagged**, before tuning | 5.5% (77) | 65.3% | 22.7% | 17 |
| **Flagged**, after tuning | **2.2% (31)** | **91.7%** | **53.6%** | **0** |
| *Phishing* label, after tuning | 0.0% (0) | 100% | 9.4% | 0 |

The dev split after tuning scored 2.2% FPR and 57.9% recall. Test and dev are close,
which suggests the changes generalize rather than memorize.

What changed between "before" and "after" (all from dev evidence):

| Change | Why |
|---|---|
| A form only counts if it asks for a password, PIN, card number or one-time code | 3% of legitimate newsletters had harmless search boxes |
| A link routed through the **sender's own** domain is not a text/destination mismatch (still flagged if the text shows a known brand or your organization) | Newsletters send links through their own click trackers |
| Display name uses **your organization's** name from an outside domain | 28% of phishing ("monkey.org Support", "FAX monkey.org"), 0% of legitimate |
| Display name claims to run your email/IT ("EMAIL SERVER", "Admin IT HelpDesk") from outside | 8% of phishing, 0.1% of legitimate |
| Links to free hosting (IPFS, r2.dev, vercel.app, Firebase storage…) | 20% of phishing, 0.2% of legitimate |
| Recipient's address in the subject | 18% of phishing, 0% of legitimate |
| Words disguised with Cyrillic look-alikes or zero-width characters | 3% of phishing, 0% of legitimate |
| Netflix, Coinbase, MetaMask, cPanel added to known brands; "D.H.L" matches DHL | Common targets missing from the list |

## Why errors remain

**False positives (31 of 1,404 legitimate).** All are "suspicious", none "phishing".

| Cause | Count | Example | Assessment |
|---|---|---|---|
| Brand name as a subdomain of an unrelated site | 9 | Lockergnome newsletter linking to `microsoft.4team.biz` | Exactly what phishers do; indistinguishable by rules. One sender accounts for all of them. |
| Reply-To elsewhere plus a URL shortener | 5 | A newsletter hosted on imakenews.net | Two weak signals adding up. |
| Links to a bare IP address | 3 | 2002-era personal sites | Rare in modern legitimate mail. |
| Other single signals (free hosting, role name, executable attachment…) | 14 | | Mixed; no single fixable pattern. |

**Missed phishing (297 of 640 labeled safe).**

| Cause | Count | What would catch it |
|---|---|---|
| No technical red flag at all: a plausible sender, a link to an ordinary-looking compromised site, and the scam lives entirely in the wording ("unusual sign-in activity, verify now") | 140 | The LLM content analyzer, which exists for exactly this and adds up to 25 points |
| One weak signal below the threshold (a URL shortener alone: 34; free hosting alone: 12; external "IT admin" name: 10…) | 157 | Content analysis or a newly registered domain would push most over 20 |

This is the intended division of labor: the rules deliberately need two pieces of evidence
before saying "phishing", and "suspicious" already tells the user not to click.

## Limitations: read before trusting these numbers

- **The legitimate mail is from 2002.** It predates DMARC, so none of it has
  `Authentication-Results`, while nearly all the phishing does. The auth checks therefore
  can't be judged fairly here: every legitimate email gets the +5 "no sender checks" note,
  and the DMARC-pass trust signal never appears on the legitimate side. Modern marketing mail
  (heavy tracking, ESP return paths) is under-represented. **Running the same script on a
  sample of your own organization's mail is the real false-positive test**: put `.eml` files
  in `eval/data/ham/yours/` and run `eval/run_eval.py --split all`.
- **The phishing comes from one person's inbox** (monkey.org). "Your organization" rules
  benefit from every email targeting the same domain. That also holds in a real deployment,
  where the recipient's domain is always known, but the exact rates will differ.
- **The LLM analyzer was not evaluated.** It needs an API key, and running 2,000 emails costs
  money. That should be the next evaluation, reporting how many of the 140 "no red flag"
  misses it recovers and what it does to false positives.
- **Network enrichment can't be evaluated retroactively.** Domains from 2023 phishing are no
  longer newly registered, and taken-down URLs have dropped off threat lists, so replaying
  them today would understate what live lookups catch.
- A few thousand emails give roughly ±1 point of uncertainty on the false-positive rate and
  ±4 on recall.

The full generated report, with per-signal firing rates and every misclassified email, is in
[RESULTS.md](RESULTS.md).
