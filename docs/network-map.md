## Network map

The dashboard's **Map** tab draws the latest scan, or the one picked in History: the router in the middle, and every device around it grouped by kind (servers, computers, printers, cameras, TVs and speakers, smart-home gear, phones, and so on). Each circle is colored by its worst finding, and a dashed ring means the device is not trusted yet. The computer running Lantern has an amber ring. Click or tab to a device to see its full card beside the map, with the same trust and label controls as the Devices tab. The search box and filter dim everything that does not match.

Where the names come from:
- **Router:** this computer's default route, when it is inside the scanned subnet. Otherwise the host that answers DNS and has a web page at a router address (`.1` or `.254`), and the legend says it was guessed.
- **Device kind:** open ports, the hostname, a randomized MAC, who made the network card, and what the device announces about itself. Hover a device to see the reason.
- **Vendor:** the maker of the network card, from the first half of the MAC address (for example Synology, Ubiquiti, Brother, Espressif, Apple). Lantern looks it up in a copy of the IEEE public registry of MAC prefixes that ships with it; nothing is looked up online. A vendor that only makes one kind of thing (network storage, cameras, printers, network gear, smart-home chips, speakers) is a strong hint about the kind; a maker of phones or PC network cards only fills in when nothing else does. A randomized ("private Wi-Fi") address has no vendor, because its bits are made up by the device. The vendor shows on device cards, in search, in text output for unnamed devices, and in JSON reports.
- **Friendly names and models:** SSDP (UPnP) and mDNS (Bonjour), for example "Living Room TV, Chromecast" or "Lexmark B2338dw". Only the name, model, manufacturer, device type, and service types are kept. Serial numbers and other TXT fields are ignored. Every value is cleaned of control characters and cut to 80 characters.

The lines in this view show what each device reaches through the router, grouped by kind. They are not cables: a scan alone cannot see switches, or which Wi-Fi access point a device uses. For that, see the switch map below.

### Switch map (managed switches)

If you have managed switches with SNMP turned on, Lantern can read them and draw which switch, and which port, each device is plugged into. The map then has a **By switch** view: the router in the middle, each switch around it (uplinks between switches drawn as arcs), and each device on the switch port where it was seen. A dashed line means several devices share that port, which usually means a Wi-Fi access point or an unmanaged switch is plugged in there. Device cards show the switch and port.

```bash
# Put the switches' read-only community in a file only you can read.
printf '%s' 'your-read-only-community' > ~/.lantern-snmp && chmod 600 ~/.lantern-snmp

# Read the switches after a scan, and store the map with it:
lantern scan --switch 192.168.1.2 --switch 192.168.1.3 --snmp-community-file ~/.lantern-snmp

# Or attach a map to the latest saved scan without rescanning:
lantern topology --switch 192.168.1.2 --snmp-community-file ~/.lantern-snmp

# Dashboard scans read the switches too:
lantern web --switch 192.168.1.2 --snmp-community-file ~/.lantern-snmp
```

The community can also come from `LANTERN_SNMP_COMMUNITY_FILE` (a path) or `LANTERN_SNMP_COMMUNITY` (the value). There is no prompt. The file gets the same checks as the API token file: no symlinks, at most 4 KiB, and on macOS and Linux no group or other permission bits. The community is never stored in the database, printed, logged, or sent to the browser.

What Lantern reads, with SNMPv2c GetRequest, GetNextRequest, and GetBulkRequest only (it has no code that can send a SetRequest, so it cannot change a switch):
- the switch's name and description (SNMPv2-MIB `sysName`, `sysDescr`), and port names (IF-MIB `ifName`, else `ifDescr`);
- the MAC address table (Q-BRIDGE-MIB `dot1qTpFdbTable`, else BRIDGE-MIB `dot1dTpFdbTable`), learned entries only;
- LLDP neighbours (LLDP-MIB `lldpRemTable`), to see which switch is cabled to which.

A port that leads to another switch you named is an uplink. Each device is placed on the non-uplink port where it was seen with the fewest other addresses. The switch with the router on one of its ports is the top of the tree. Devices no switch saw (Wi-Fi through the router, a switch you did not name, or an unmanaged switch upstream) are drawn under "Not seen on a switch".

Limits: switch addresses must be private IPv4 addresses, as for scans; at most 16 switches per run, read 4 at a time; 2 seconds per request with one retry; at most 20000 rows per table and 30 seconds per switch. A switch that does not answer is listed with the reason and the rest still draw. SNMPv3 is not supported: its privacy mode needs AES, which Python's standard library does not include, and Lantern has no third-party dependencies. If your switches only allow SNMPv3, the switch map is not available yet.

The demo (`lantern demo`, or **Run demo** on the dashboard) includes two example switches, so you can see the switch view without any hardware.

Scans saved before 1.1.0 still draw. They have no stored router or names, so the router is guessed and devices are grouped by ports and hostnames only.

