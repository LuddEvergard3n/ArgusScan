# Declared limitations

- The first target is Linux IPv4. Windows-native raw scanning and IPv6 are outside
  the initial release.
- Idle scan is not implemented because it requires IP ID sequence analysis through
  a suitable third-party zombie host.
- OS fingerprinting is heuristic, not deterministic. Similar stacks and network
  middleboxes can produce indistinguishable evidence.
- UDP silence is structurally ambiguous between an open service that does not reply
  to the selected probe and a filtered packet.
- FIN, NULL and XMAS depend on target-stack behavior and are commonly uninformative
  against Windows-style reset behavior.
- ACK identifies filtered versus unfiltered paths; it does not establish whether a
  TCP port is open.
- TCP Window relies on historical RST-window behavior and is not reliable across all
  modern systems.
- Service detection uses bounded, non-authenticating probes and cannot identify
  every customized or encrypted service.
- The current service database covers a deliberately small set of greetings and
  probes: SSH, HTTP, Redis, MySQL, FTP and SMTP. TLS negotiation is not implemented.
- Timing profiles reduce or increase traffic rates but cannot guarantee accuracy,
  non-detection or absence of network impact.
- Captured IPv4 fragments are ignored. ArgusScan does not reassemble fragmented
  TCP, UDP or ICMP responses.
- TCP and UDP raw scans use bounded event-driven probe tables. UDP remains slow by
  protocol design when many services are silent, rate-limit ICMP, or require a
  protocol-specific request before replying.
- CIDR and last-octet ranges are capped at 4,096 targets and currently support text
  output only. CIDR expansion includes network and broadcast addresses.
- Default OS scoring uses one SYN/ACK. Optional `--os-detect` adds standard,
  minimal-option and ECN observations plus closed-port reset behavior when the
  input contains a closed port. The signature table and fixture corpus remain too
  small for narrow OS or version claims.
- There is no CVE database, exploit engine, GUI, distributed scanner or Nmap backend.
