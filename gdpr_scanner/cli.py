"""Startpunkt på kommandolinjen for GDPR PII-skanneren."""
import argparse
import sys

from gdpr_scanner.report import console_report, json_report
from gdpr_scanner.scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gdpr-scanner",
        description="Skann filer og mapper etter personopplysninger (PII) og "
        "rapporter hvor de ligger: automatisk kartlegging av data for GDPR.",
    )
    parser.add_argument("path", help="Fil eller mappe som skal skannes")
    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Utskriftsformat (standard: console)",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Avslutt med kode 1 hvis det finnes PII (nyttig i CI-pipelines)",
    )
    args = parser.parse_args(argv)

    result = scan_path(args.path)

    if args.format == "json":
        print(json_report(result))
    else:
        print(console_report(result))

    if args.fail_on_findings and result.total_matches > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
