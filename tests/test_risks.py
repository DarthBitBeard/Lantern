from lantern.discovery import guess_subnet, validate_subnet
from lantern.ports import findings_for_ports
from lantern.webapp import WEB_DIR


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


def test_dashboard_assets_present():
    """pip install / Docker must ship lantern/web, not only .py files."""
    for name in ("index.html", "styles.css", "app.js"):
        path = WEB_DIR / name
        assert path.is_file(), f"missing dashboard asset: {path}"


def test_guess_subnet_private_or_none():
    """Auto-detect must never return a public or loopback network."""
    subnet = guess_subnet()
    if subnet is None:
        return
    network = validate_subnet(subnet)
    assert network.is_private
    assert network.prefixlen >= 16
