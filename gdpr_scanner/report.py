"""Turn scan results into human- and machine-readable reports."""
import json

from gdpr_scanner.scanner import ScanResult

# Friendly labels for the console report.
LABELS = {
    "email": "Email addresses",
    "norwegian_fnr": "Norwegian national IDs (fødselsnummer)",
    "payment_card": "Payment card numbers",
    "phone": "Phone numbers",
    "ip_address": "IP addresses",
}


def console_report(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("GDPR PII SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Files scanned : {result.files_scanned}")
    lines.append(f"Files skipped : {result.files_skipped} (non-text)")
    lines.append(f"Files with PII: {len(result.flagged_files)}")
    lines.append(f"Total findings: {result.total_matches}")
    lines.append("")

    if not result.total_counts:
        lines.append("No personal data detected.")
        return "\n".join(lines)

    lines.append("Findings by type:")
    for pii_type, count in sorted(
        result.total_counts.items(), key=lambda x: -x[1]
    ):
        label = LABELS.get(pii_type, pii_type)
        lines.append(f"  {label:<42} {count}")
    lines.append("")

    lines.append("Per file (values are masked):")
    for f in result.flagged_files:
        lines.append(f"\n  {f.path}")
        for m in f.matches:
            label = LABELS.get(m.pii_type, m.pii_type)
            lines.append(f"    line {m.line:<5} {label:<42} {m.masked}")

    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    data = {
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "files_with_pii": len(result.flagged_files),
            "total_findings": result.total_matches,
            "findings_by_type": result.total_counts,
        },
        "files": [
            {
                "path": f.path,
                "counts": f.counts,
                "matches": [
                    {"type": m.pii_type, "line": m.line, "value_masked": m.masked}
                    for m in f.matches
                ],
            }
            for f in result.flagged_files
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
