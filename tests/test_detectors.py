from gdpr_scanner.detectors import scan_line, _valid_fnr, _valid_card


def types(line):
    return {m.pii_type for m in scan_line(line, 1)}


def test_email_detected():
    assert "email" in types("contact me at jane.doe@example.com please")


def test_valid_fnr_detected():
    assert "norwegian_fnr" in types("id 15068700059 on file")


def test_invalid_fnr_ignored():
    # 11 digits but wrong checksum -> not flagged as a national ID
    assert "norwegian_fnr" not in types("number 12345678901 here")


def test_valid_card_detected():
    assert "payment_card" in types("card 4111 1111 1111 1111 used")


def test_invalid_card_ignored():
    assert "payment_card" not in types("code 1234 5678 9012 3456 xx")


def test_phone_detected():
    assert "phone" in types("ring meg på +47 912 34 567")


def test_ip_detected():
    assert "ip_address" in types("from host 192.168.10.45 at noon")


def test_clean_line_has_no_findings():
    assert types("just a normal sentence with no personal data") == set()


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
