# GDPR PII Scanner

An automation tool that scans files and folders for personal data (PII) and reports where it lives. It answers a question every GDPR programme has to answer first: **where is our personal data, and what kind?**

Finding that out by hand does not scale. This tool does it automatically, so it can run on a schedule or inside a CI pipeline.

## Why this matters for GDPR

- **Data discovery / mapping** – you cannot protect or delete personal data you do not know you have. This is the groundwork for a **Record of Processing Activities (Article 30)**.
- **Data minimisation (Article 5)** – surfacing PII in logs, exports and scratch files shows where data is being kept that probably should not be.
- **Breach readiness** – knowing which files hold national IDs or card numbers tells you how serious an exposure is.

## What it detects

| Type | How false positives are avoided |
|------|-------------------------------|
| Email addresses | Standard pattern |
| Norwegian national IDs (fødselsnummer) | Validated with the official mod-11 control digits |
| Payment card numbers | Validated with the Luhn algorithm |
| Phone numbers (Norwegian) | Exactly 8 digits, not part of a longer number |
| IPv4 addresses | Range-checked octets |

Validation matters: an 11-digit number is only reported as a national ID if its checksum is valid, and a card number only if it passes Luhn. That keeps the report trustworthy instead of noisy.

## Privacy by design

The report **masks every value it finds** (`*********59`), so the output itself does not become a new pile of personal data. A tool built to help with GDPR should not leak PII in its own logs.

## Usage

No dependencies to install for running it, it uses only the Python standard library.

```bash
# Scan a folder
python -m gdpr_scanner sample_data/

# Machine-readable output
python -m gdpr_scanner sample_data/ --format json > report.json

# Fail the build if any PII is found (for CI pipelines)
python -m gdpr_scanner ./exports --fail-on-findings
```

### Example output

```
============================================================
GDPR PII SCAN REPORT
============================================================
Files scanned : 3
Files skipped : 0 (non-text)
Files with PII: 2
Total findings: 13

Findings by type:
  Email addresses                            5
  Phone numbers                              4
  Norwegian national IDs (fødselsnummer)     2
  Payment card numbers                       1
  IP addresses                               1
```

## Automation

Because it exits with code `1` when it finds PII, it drops straight into a pipeline. Example GitHub Actions step that blocks a commit from introducing personal data into tracked files:

```yaml
- name: GDPR PII scan
  run: python -m gdpr_scanner . --fail-on-findings
```

The same command can run as a scheduled job to keep re-scanning shared folders over time.

## Project structure

```
gdpr_scanner/
  detectors.py   # regex patterns + fnr/Luhn validators, with value masking
  scanner.py     # walk files, scan line by line, aggregate results
  report.py      # console and JSON reports
  cli.py         # command-line interface
sample_data/     # fake data to try it on (no real people)
tests/           # 14 tests for the detectors and the scanner
```

## Tests

```bash
pytest -q
```

Covers each detector, checksum validation (a wrong fødselsnummer or card number is **not** flagged), value masking, and a full scan of the sample folder.

## Notes

- All data in `sample_data/` is synthetic. The national IDs are checksum-valid but do not belong to real people, and the card number is the standard Visa test number.
- Detection is pattern-based, so it finds structured identifiers well. Free-text names and addresses would need NLP, a natural next step.

## Tech

Python (standard library only) · pytest
