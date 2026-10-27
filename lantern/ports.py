"""Port and risk definitions.

No network calls here. Every rule is plain English, with a fix a
non-security person can follow. Severity order: critical, high,
medium, low, info.
"""

# port -> (service, severity, title, fix)
PORT_RULES = {
    21: ("FTP", "high", "FTP is open",
         "FTP sends passwords in plain text. Turn FTP off, or switch to SFTP."),
    22: ("SSH", "low", "SSH is open",
         "OK if you use it. Use key login, turn off password login, and keep it off the internet."),
    23: ("Telnet", "critical", "Telnet is open",
         "Telnet sends everything, including passwords, in plain text. Turn Telnet off and use SSH instead."),
    25: ("SMTP", "medium", "Mail service is open",
         "Only expected on a mail server. Otherwise turn it off."),
    53: ("DNS", "low", "DNS is open",
         "Expected on a router or Pi-hole/AdGuard. Make sure it is not open to the internet."),
    80: ("HTTP", "low", "Web service is open",
         "Check it needs no login over plain HTTP. Prefer HTTPS."),
    110: ("POP3", "medium", "POP3 mail is open",
         "Old mail protocol. Turn it off unless you know you need it."),
    135: ("RPC", "medium", "Windows RPC is open",
         "Normal on Windows, but it should never be reachable from the internet."),
    139: ("NetBIOS", "medium", "NetBIOS is open",
         "Old Windows sharing. Turn it off if you do not use old file sharing."),
    143: ("IMAP", "medium", "IMAP mail is open",
         "Only expected on a mail server. Otherwise turn it off."),
    443: ("HTTPS", "info", "Secure web service is open",
         "Normal for routers, cameras, and servers. Make sure it asks for a login."),
    445: ("SMB", "high", "Windows file sharing (SMB) is open",
         "Fine inside your home if you use file sharing. Never expose it to the internet, and turn off SMBv1."),
    1433: ("MSSQL", "high", "SQL Server is open",
         "Database ports should only be reachable by the apps that need them, never by the whole network."),
    3306: ("MySQL", "high", "MySQL is open",
         "Database ports should only be reachable by the apps that need them, never by the whole network."),
    3389: ("RDP", "high", "Remote Desktop is open",
         "RDP is a common break-in target. Turn it off when not in use, or reach it only over a VPN like Tailscale."),
    5432: ("PostgreSQL", "high", "PostgreSQL is open",
         "Database ports should only be reachable by the apps that need them, never by the whole network."),
    5900: ("VNC", "high", "VNC remote screen is open",
         "VNC is often weakly protected. Turn it off, or use it only over a VPN."),
    6379: ("Redis", "critical", "Redis is open",
         "Redis has no login by default. Bind it to localhost only, or set a strong password."),
    8080: ("HTTP-alt", "low", "Web service is open on 8080",
         "Check what app this is, and make sure it asks for a login."),
    8443: ("HTTPS-alt", "info", "Secure web service is open on 8443",
         "Normal for routers and servers. Make sure it asks for a login."),
    8888: ("HTTP-alt", "low", "Web service is open on 8888",
         "Check what app this is, and make sure it asks for a login."),
    9000: ("HTTP-alt", "low", "Web service is open on 9000",
         "Check what app this is, and make sure it asks for a login."),
    9090: ("HTTP-alt", "low", "Web service is open on 9090",
         "Check what app this is, and make sure it asks for a login."),
    32400: ("Plex", "info", "Plex is open",
         "Normal for a Plex server. Keep Plex updated."),
    8096: ("Jellyfin", "info", "Jellyfin is open",
         "Normal for a Jellyfin server. Make sure it asks for a login, and prefer HTTPS or VPN access remotely."),
    8123: ("Home Assistant", "info", "Home Assistant is open",
         "Normal for Home Assistant. Make sure it asks for a login, and keep it updated."),
}

# Ports scanned in a normal run. Kept small on purpose: fast, quiet,
# and no brute force, no exploits, no password guessing, ever.
DEFAULT_PORTS = sorted(PORT_RULES.keys())

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def risk_for_port(port):
    """Return (service, severity, title, fix) for a port, or None."""
    return PORT_RULES.get(port)


def findings_for_ports(open_ports):
    """Turn a list of open ports into sorted risk findings."""
    findings = []
    for port in open_ports:
        rule = PORT_RULES.get(port)
        if rule:
            service, severity, title, fix = rule
            findings.append(
                {"port": port, "service": service, "severity": severity,
                 "title": title, "fix": fix}
            )
        else:
            findings.append(
                {"port": port, "service": "unknown", "severity": "low",
                 "title": f"Unknown service on port {port}",
                 "fix": "Find what app opened this port, and close it if you do not need it."}
            )
    findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 9))
    return findings
