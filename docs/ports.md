## What it scans

33 ports, chosen for risk, not coverage: Telnet, FTP, SSH, SMB, RDP, VNC, databases (including MongoDB, Elasticsearch, Memcached), mail, web, the Docker API, MQTT, camera streams (RTSP), printers, plus homelab services (Jellyfin 8096, Plex 32400, Home Assistant 8123). Each open port maps to a severity, a plain English title, and a fix step in `lantern/ports.py`.

