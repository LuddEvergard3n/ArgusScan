# Threat model

## Authorization boundary

ArgusScan is intended for owned systems, labs and explicitly authorized security
assessments. It does not include exploitation, credential attacks, spoofed-source
scans, decoys, distributed scanning or automatic vulnerability lookup.

## How defenders can observe it

SYN scans create incomplete handshakes across ports. FIN, NULL and XMAS scans use
unusual flag combinations. ACK scans generate unsolicited acknowledgments. UDP
scans can generate bursts of ICMP errors. IDS/IPS products can correlate these
patterns across destinations, ports and time even when probes are delayed.

Timing templates exist for traffic control, repeatability and reducing load on
sensitive networks. They do not promise invisibility or IDS evasion.

Active OS detection is opt-in because it adds two probes to the selected open port
and, when available, one probe to a closed port. It is intended for a controlled,
authorized lab and does not attempt to conceal those observations.

## Hostile response model

The target or network may return truncated, malformed, duplicated, delayed,
contradictory or forged packets. Services may send oversized or control-character
banners. DNS may resolve to multiple or changing addresses. A target may remain
silent deliberately.

Therefore parsers and outputs must be length-bounded, packet correlation must reject
unrelated traffic, queue sizes must be capped and terminal output must escape
untrusted bytes.

## Local risks

Raw socket access raises the impact of memory-safety defects. Parsing, service
detection and formatting should not retain elevated privileges unnecessarily.
Output paths must not overwrite unrelated files, and interrupted scans must release
sockets, capture handles, jobs and buffers.
