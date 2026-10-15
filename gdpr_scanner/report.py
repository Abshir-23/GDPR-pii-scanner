"""Gjør skanneresultater om til rapporter for mennesker og maskiner."""
import json

from gdpr_scanner.scanner import ScanResult

# Lesbare navn til konsollrapporten.
LABELS = {
    "email": "E-postadresser",
    "norwegian_fnr": "Norske fødselsnumre",
    "payment_card": "Betalingskortnumre",
    "phone": "Telefonnumre",
    "ip_address": "IP-adresser",
}


def console_report(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("GDPR PII-SKANNERAPPORT")
    lines.append("=" * 60)
    lines.append(f"Filer skannet      : {result.files_scanned}")
    lines.append(f"Filer hoppet over  : {result.files_skipped} (ikke tekst)")
    lines.append(f"Filer med PII      : {len(result.flagged_files)}")
    lines.append(f"Totalt antall funn : {result.total_matches}")
    lines.append("")

    if not result.total_counts:
        lines.append("Fant ingen personopplysninger.")
        return "\n".join(lines)

    lines.append("Funn per type:")
    for pii_type, count in sorted(
        result.total_counts.items(), key=lambda x: -x[1]
    ):
        label = LABELS.get(pii_type, pii_type)
        lines.append(f"  {label:<42} {count}")
    lines.append("")

    lines.append("Per fil (verdiene er maskert):")
    for f in result.flagged_files:
        lines.append(f"\n  {f.path}")
        for m in f.matches:
            label = LABELS.get(m.pii_type, m.pii_type)
            lines.append(f"    linje {m.line:<5} {label:<42} {m.masked}")

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
