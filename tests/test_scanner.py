from pathlib import Path

from gdpr_scanner.scanner import scan_path

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data"


def test_scan_sample_directory():
    result = scan_path(SAMPLE)
    assert result.files_scanned == 3          # csv, txt, md
    assert len(result.flagged_files) == 2     # clean_file.md has nothing
    assert result.total_counts.get("email", 0) >= 3
    assert result.total_counts.get("norwegian_fnr", 0) == 2
    assert result.total_counts.get("payment_card", 0) == 1


def test_clean_file_not_flagged():
    result = scan_path(SAMPLE)
    flagged = {f.path for f in result.flagged_files}
    assert not any(p.endswith("clean_file.md") for p in flagged)


def test_scan_single_file():
    result = scan_path(SAMPLE / "customers.csv")
    assert result.files_scanned == 1
    assert result.total_matches > 0
