"""Command-line entry point for the GDPR PII scanner."""
import argparse
import sys

from gdpr_scanner.report import console_report, json_report
from gdpr_scanner.scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gdpr-scanner",
        description="Scan files and folders for personal data (PII) and "
        "report where it lives - automated data discovery for GDPR.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 1 if any PII is found (useful in CI pipelines)",
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
