"""Detectors for common types of personal data (PII).

Each detector is a regex plus, where it matters, a validator that rejects
false positives (a checksum for Norwegian national IDs, the Luhn algorithm
for payment cards). Detecting on structure alone is noisy; validating makes
the report trustworthy.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    pii_type: str
    value: str
    line: int

    @property
    def masked(self) -> str:
        """Mask the value so the report itself does not leak personal data.

        Keeps the last 2 characters for context, hides the rest.
        """
        v = self.value
        if len(v) <= 2:
            return "*" * len(v)
        return "*" * (len(v) - 2) + v[-2:]


# --- Regex patterns -------------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Norwegian phone: optional +47 / 0047, then exactly 8 digits with optional
# single spaces (handles 2-2-2-2 and 3-2-3 groupings). The lookarounds make
# sure we are not matching 8 digits that are really part of a longer spaced
# run such as a 16-digit payment card.
_PHONE_NO = re.compile(
    r"(?<!\d)(?<!\d )(?:(?:\+47|0047)[ ]?)?\d(?:[ ]?\d){7}(?![ ]?\d)"
)
_FNR = re.compile(r"(?<!\d)\d{11}(?!\d)")                 # Norwegian fødselsnummer
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")    # payment card
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def _valid_fnr(value: str) -> bool:
    """Validate a Norwegian fødselsnummer using its two control digits (mod 11)."""
    if len(value) != 11 or not value.isdigit():
        return False
    d = [int(c) for c in value]
    w1 = [3, 7, 6, 1, 8, 9, 4, 5, 2]
    w2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    k1 = 11 - (sum(a * b for a, b in zip(w1, d[:9])) % 11)
    k1 = 0 if k1 == 11 else k1
    if k1 == 10 or k1 != d[9]:
        return False
    k2 = 11 - (sum(a * b for a, b in zip(w2, d[:10])) % 11)
    k2 = 0 if k2 == 11 else k2
    if k2 == 10 or k2 != d[10]:
        return False
    return True


def _valid_card(value: str) -> bool:
    """Validate a payment card number with the Luhn algorithm."""
    digits = [int(c) for c in re.sub(r"[ -]", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def scan_line(line: str, line_number: int) -> list[Match]:
    """Return all PII matches found in a single line of text."""
    matches: list[Match] = []

    for m in _EMAIL.finditer(line):
        matches.append(Match("email", m.group(), line_number))

    for m in _FNR.finditer(line):
        if _valid_fnr(m.group()):
            matches.append(Match("norwegian_fnr", m.group(), line_number))

    for m in _CARD.finditer(line):
        if _valid_card(m.group()):
            matches.append(Match("payment_card", m.group(), line_number))

    for m in _PHONE_NO.finditer(line):
        # Avoid double-counting an 11-digit fnr as a phone number
        digits = re.sub(r"\D", "", m.group())
        if len(digits) == 11 and _valid_fnr(digits):
            continue
        matches.append(Match("phone", m.group(), line_number))

    for m in _IPV4.finditer(line):
        matches.append(Match("ip_address", m.group(), line_number))

    return matches
