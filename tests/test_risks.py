from lantern.ports import findings_for_ports
from lantern.discovery import validate_subnet


def test_telnet_is_critical():
    findings = findings_for_ports([23, 443])
    assert findings[0]["port"] == 23
    assert findings[0]["severity"] == "critical"


def test_public_subnet_refused():
    try:
        validate_subnet("8.8.8.0/24")
    except ValueError:
        return
    raise AssertionError("public subnet was not refused")


def test_too_large_subnet_refused():
    try:
        validate_subnet("10.0.0.0/8")
    except ValueError:
        return
    raise AssertionError("oversized subnet was not refused")
