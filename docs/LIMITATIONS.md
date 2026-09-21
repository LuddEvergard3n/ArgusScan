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
- Timing profiles reduce or increase traffic rates but cannot guarantee accuracy,
  non-detection or absence of network impact.
- There is no CVE database, exploit engine, GUI, distributed scanner or Nmap backend.

