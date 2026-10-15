"""Detektorer for vanlige typer personopplysninger (PII).

Hver detektor er et regex-mønster, og der det betyr noe, en validering som
avviser falske treff (kontrollsifre for norske fødselsnumre, Luhn-algoritmen
for betalingskort). Å detektere bare på struktur gir mye støy; validering gjør
rapporten pålitelig.
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
        """Masker verdien slik at rapporten selv ikke lekker personopplysninger.

        Beholder de 2 siste tegnene som kontekst og skjuler resten.
        """
        v = self.value
        if len(v) <= 2:
            return "*" * len(v)
        return "*" * (len(v) - 2) + v[-2:]


# --- Regex-mønstre --------------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Norsk telefonnummer: valgfri +47 / 0047, deretter nøyaktig 8 siffer med
# valgfrie enkle mellomrom (håndterer grupperingene 2-2-2-2 og 3-2-3).
# Lookaround-delene sørger for at vi ikke treffer 8 siffer som egentlig er
# en del av en lengre tallrekke med mellomrom, som et betalingskort på 16 siffer.
_PHONE_NO = re.compile(
    r"(?<!\d)(?<!\d )(?:(?:\+47|0047)[ ]?)?\d(?:[ ]?\d){7}(?![ ]?\d)"
)
_FNR = re.compile(r"(?<!\d)\d{11}(?!\d)")                 # norsk fødselsnummer
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")    # betalingskort
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def _valid_fnr(value: str) -> bool:
    """Valider et norsk fødselsnummer med de to kontrollsifrene (mod 11)."""
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
    """Valider et betalingskortnummer med Luhn-algoritmen."""
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
    """Returner alle PII-treff i én tekstlinje."""
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
        # Unngå å telle et fødselsnummer på 11 siffer to ganger som telefonnummer
        digits = re.sub(r"\D", "", m.group())
        if len(digits) == 11 and _valid_fnr(digits):
            continue
        matches.append(Match("phone", m.group(), line_number))

    for m in _IPV4.finditer(line):
        matches.append(Match("ip_address", m.group(), line_number))

    return matches
