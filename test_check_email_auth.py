from check_email_auth import all_qualifier, parse_tags


def test_all_qualifier():
    assert all_qualifier("v=spf1 include:_spf.google.com ~all") == "~all"
    assert all_qualifier("v=spf1 ip4:1.2.3.4 -all") == "-all"
    assert all_qualifier("v=spf1 a mx all") == "+all"
    assert all_qualifier("v=spf1 redirect=_spf.example.com") is None


def test_parse_tags():
    tags = parse_tags("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100")
    assert tags["p"] == "reject"
    assert tags["rua"] == "mailto:dmarc@example.com"
    assert parse_tags("v=DMARC1;p=none")["p"] == "none"


if __name__ == "__main__":
    test_all_qualifier()
    test_parse_tags()
    print("tests ok")
