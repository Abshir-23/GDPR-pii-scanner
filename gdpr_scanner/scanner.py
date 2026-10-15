"""Gå gjennom en sti, skann filer etter PII og samle funnene."""
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from gdpr_scanner.detectors import Match, scan_line

# Skann bare tekstfiler; binærfiler hoppes over.
TEXT_EXTENSIONS = {".txt", ".csv", ".log", ".json", ".md", ".tsv", ".yml", ".yaml"}


@dataclass
class FileResult:
    path: str
    matches: list[Match] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return dict(Counter(m.pii_type for m in self.matches))


@dataclass
class ScanResult:
    files: list[FileResult] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    @property
    def flagged_files(self) -> list[FileResult]:
        return [f for f in self.files if f.matches]

    @property
    def total_counts(self) -> dict[str, int]:
        c: Counter = Counter()
        for f in self.files:
            c.update(f.counts)
        return dict(c)

    @property
    def total_matches(self) -> int:
        return sum(len(f.matches) for f in self.files)


def scan_file(path: Path) -> FileResult:
    result = FileResult(path=str(path))
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh, start=1):
                result.matches.extend(scan_line(line, i))
    except OSError:
        pass
    return result


def scan_path(target: str | Path) -> ScanResult:
    """Skann én fil, eller gå rekursivt gjennom en mappe."""
    target = Path(target)
    result = ScanResult()

    if target.is_file():
        paths = [target]
    else:
        paths = sorted(p for p in target.rglob("*") if p.is_file())

    for path in paths:
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            result.files_skipped += 1
            continue
        result.files.append(scan_file(path))
        result.files_scanned += 1

    return result
