## Limitations

What this version does, and what it does not do.

- **Inventory is edited in the CLI and shown on the dashboard.** `lantern asset` writes owner, location, tags, criticality, and notes ([0.4.0](../CHANGELOG.md#040---2026-10-30)). The static page does not embed them. A caller with the access token receives them on the scan API, and the device cards render them ([0.5.0](../CHANGELOG.md#050---2026-11-02)). The dashboard has no form that edits inventory.
- **One token.** `GET /api/v1/status` reports `role` `admin`. There is no read-only token and no second role.
- **Plain HTTP.** The dashboard does not speak TLS. With `--allow-lan` the token and the scan data cross the network in clear text. See [SECURITY.md](../SECURITY.md#known-limitations).
- **SNMP was not checked on a real switch.** The switch map sends read-only SNMPv2c and was exercised against a simulated agent ([1.2.0](../CHANGELOG.md#120---2026-11-05)). SNMPv3 is not supported.
- **Windows binaries are not code-signed** ([1.1.0](../CHANGELOG.md#110---2026-11-05)). SmartScreen can warn. See [Windows installer](../README.md#windows-installer).
- **Not in this version:** device fingerprinting, a vulnerability database or matcher, and a watch mode or local alerts. Hostnames are stored as the device reports them, and the saved HTML report has no Content-Security-Policy of its own. Scans stay inside the RFC1918 ranges and the 1024-address cap in [Safety rules](safety.md#safety-rules-enforced-in-code).

