"""Factual reference data the rules cite.

Everything here is sourced from public standards or UniFi's own documented
behavior, so findings that reference it stay grounded:

* IEEE 802.11 reason codes (deauth/disassoc) — IEEE Std 802.11, Table 9-49.
* DHCP/DNS/PoE/STP terminology — RFC 2131, RFC 1035, IEEE 802.3af/at, 802.1D.
* UniFi service ports — Ubiquiti "UniFi - Ports Used" help article.

Thresholds (flap counts, error rates) are conservative defaults chosen to
avoid false positives; they are documented inline so a reviewer can judge them.
"""

from __future__ import annotations

# IEEE 802.11 reason codes most commonly seen in Wi-Fi disconnect logs.
# Source: IEEE Std 802.11-2020, Table 9-49 (Reason codes).
WIFI_REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station (STA) is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving BSS",
    9: "STA requesting (re)association is not authenticated",
    13: "Invalid information element",
    14: "Message integrity code (MIC) failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Information element in 4-Way Handshake differs",
    23: "IEEE 802.1X authentication failed",
    34: "Disassociated due to excessive frame loss / poor channel conditions",
}

# UniFi service ports (Ubiquiti "UniFi - Ports Used").
UNIFI_PORTS = {
    "inform": 8080,        # device -> controller inform (TCP)
    "stun": 3478,          # device <-> controller STUN (UDP)
    "https_gui": 443,      # UniFi OS GUI (TCP)
    "mongo": 27117,        # Network application database (TCP, localhost)
    "discovery": 10001,    # device discovery (UDP)
    "speedtest": 6789,     # mobile speed test (TCP)
}

# Substrings that reliably indicate a kernel out-of-memory kill.
OOM_SIGNATURES = (
    "Out of memory: Killed process",
    "invoked oom-killer",
    "Killed process",
)

# Storage-full signatures (ext4/overlayfs and app-level).
DISK_FULL_SIGNATURES = (
    "No space left on device",
    "write error: No space left",
    "ENOSPC",
)

# DFS radar detection (forces an AP off a 5 GHz channel).
DFS_RADAR_SIGNATURES = (
    "radar detected",
    "DFS",
    "found a radar",
)

# WAN/interface link-state phrasing emitted by UniFi/Linux.
WAN_DOWN_SIGNATURES = (
    "Link down",
    "link down",
    "WAN_LOCAL down",
    "carrier lost",
    "NIC Link is Down",
)
WAN_UP_SIGNATURES = (
    "Link up",
    "link up",
    "carrier acquired",
    "NIC Link is Up",
)

# Authentication failure signatures (SSH/console brute force).
AUTH_FAIL_SIGNATURES = (
    "Failed password",
    "authentication failure",
    "Invalid user",
    "Connection closed by authenticating user",
)

# Reference URLs for citation in findings.
REFS = {
    "ieee80211": "IEEE Std 802.11-2020, Table 9-49 (Reason codes)",
    "unifi_ports": "Ubiquiti Help: 'UniFi - Ports Used'",
    "rfc2131": "RFC 2131 (DHCP)",
    "rfc1035": "RFC 1035 (DNS)",
    "poe": "IEEE 802.3af/at (Power over Ethernet)",
    "stp": "IEEE 802.1D (Spanning Tree Protocol)",
    "udm_ssh": "Ubiquiti Help: 'UniFi - Connect with Debug / SSH'",
}
