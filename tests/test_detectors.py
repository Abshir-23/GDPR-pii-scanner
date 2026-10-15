from gdpr_scanner.detectors import scan_line, _valid_fnr, _valid_card


def types(line):
    return {m.pii_type for m in scan_line(line, 1)}


def test_email_detected():
    assert "email" in types("kontakt meg på jane.doe@example.com")


def test_valid_fnr_detected():
    assert "norwegian_fnr" in types("fnr 15068700059 er registrert")


def test_invalid_fnr_ignored():
    # 11 siffer, men feil kontrollsiffer -> blir ikke flagget som fødselsnummer
    assert "norwegian_fnr" not in types("nummer 12345678901 her")


def test_valid_card_detected():
    assert "payment_card" in types("kort 4111 1111 1111 1111 brukt")


def test_invalid_card_ignored():
    assert "payment_card" not in types("kode 1234 5678 9012 3456 xx")


def test_phone_detected():
    assert "phone" in types("ring meg på +47 912 34 567")


def test_ip_detected():
    assert "ip_address" in types("fra vert 192.168.10.45 klokken tolv")


def test_clean_line_has_no_findings():
    assert types("bare en vanlig setning uten personopplysninger") == set()


def test_masking_hides_most_of_value():
    m = scan_line("id 15068700059 x", 1)[0]
    assert m.masked.endswith("59")
    assert m.masked.count("*") == len(m.value) - 2


def test_fnr_validator_unit():
    assert _valid_fnr("15068700059")
    assert not _valid_fnr("15068700058")


def test_card_validator_unit():
    assert _valid_card("4111111111111111")
    assert not _valid_card("4111111111111112")
