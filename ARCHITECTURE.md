# ArgusScan architecture

## Design goals

ArgusScan is small enough to explain from packet bytes to final JSON. It uses
bounded queues, bounded input, explicit deadlines and a fixed worker pool. Raw
packet transmission is event-driven; it is not implemented as one thread per port.

## Data flow

```text
target parser -> scheduler/rate limiter -> packet sender
                         |                       |
                         v                       v
                  outstanding probes <- capture/parser
                         |
                         v
                  state inference -> service/OS evidence -> output
```

Blocking TCP Connect and application-level service probes use a bounded worker
pool. Raw transmission uses a scheduler, a capture loop and a probe table keyed by
protocol, addresses, ports and correlation data such as TCP sequence numbers.

The TCP raw implementation reuses one capture handle and one raw socket. A bounded
outstanding-probe table tracks packet bytes, source/destination ports, TCP sequence,
attempt count and monotonic deadline. Responses are parsed once and correlated to
active entries; expired entries are retried or finalized. Timing profiles cap both
parallel and outstanding probes, apply inter-probe delay and enforce host timeout.
TCP and UDP use protocol-specific tables with the same scheduling model.

Response classification is isolated from capture and transmission. The pure
classifier consumes a parsed IPv4 view plus the probe identity and returns either a
terminal state or no match. Both live raw schedulers call this module, while unit
fixtures exercise tuple correlation, sequence acknowledgment, ICMP quotations,
duplicates, reordering and truncation without raw-socket privileges.

## Target expansion

The parser accepts one hostname/IPv4 address, IPv4 CIDR, or a range whose final
octet is abbreviated after `-`. Expansion is bounded to 4,096 targets before any
scan begins. CIDR expansion includes every address in the block, including network
and broadcast addresses; callers remain responsible for selecting an appropriate
authorized range.

## Implemented TCP Connect path

The current CLI resolves one hostname to its first IPv4 address, normalizes a
comma/range port specification, and allocates results in sorted port order. A fixed
pool consumes a bounded ring queue. Each worker performs a nonblocking `connect`,
waits with `poll` against the selected timing profile and records latency using a
monotonic clock. `ECONNREFUSED` becomes `closed`; successful completion becomes
`open`; timeout and other network failures become `filtered`. A host-wide monotonic
deadline is shared by queued and active jobs, and each `poll` is capped by the time
remaining before that deadline.

## Response semantics

| Scan | Observation | Result |
| --- | --- | --- |
| TCP Connect | connection established | open |
| TCP Connect | connection refused | closed |
| TCP Connect | timeout or filtering error | filtered |
| TCP SYN | SYN/ACK | open |
| TCP SYN | RST | closed |
| TCP SYN | timeout or prohibitive ICMP | filtered |
| TCP FIN/NULL/XMAS | RST | closed |
| TCP FIN/NULL/XMAS | no response | open\|filtered |
| TCP ACK | RST | unfiltered |
| TCP ACK | no response or prohibitive ICMP | filtered |
| TCP Window | RST window heuristic | open or closed guess |
| UDP | UDP response | open |
| UDP | ICMP port unreachable | closed |
| UDP | no response | open\|filtered |

TCP Window is explicitly heuristic. FIN, NULL and XMAS are often ineffective
against stacks that reset all unsolicited segments, including common Windows
behavior.

## OS fingerprinting

Fingerprinting will retain observations rather than only a guessed label:

- observed and estimated initial TTL;
- IP DF and IP ID behavior;
- TCP window;
- MSS, SACK, timestamp and window-scale presence and values;
- exact TCP option ordering and padding;
- response behavior across multiple active probes.

Signatures produce explainable weighted scores. A result is probabilistic and may
be altered by routing, NAT, firewalls, proxies or kernel configuration.

The default SYN scan extracts evidence from each SYN/ACK and scores broad
`Linux-like`, `Windows-like` or `BSD/macOS-like` signatures from a compiled,
versioned table. With explicit `--os-detect`, the first open port is observed with
standard, minimal-option and ECN SYN profiles. A closed port from the same input,
when available, contributes reset behavior. The aggregate records TTL/DF
consistency, IP ID pattern, timestamp behavior, ECN echo and the closed-port result.

The signature-table version and probe mode are emitted with text, JSON and XML.
Confidence remains capped, and no narrow kernel or OS version is claimed. This is
an intentionally small evidence set rather than a compatibility claim with mature
fingerprint databases.

## Service detection

Service detection reconnects only to TCP ports already classified open and is
opt-in through `--services`. It listens briefly before sending anything, then uses
bounded non-authenticating probes for HTTP and Redis where appropriate. SSH and
MySQL greetings are recognized by content rather than assuming the conventional
port. Banner storage is capped at 512 bytes and text output escapes control bytes.

## Output

All scan paths are normalized into a report model before formatting. Text, JSON and
XML share the same state, latency, fingerprint, service and banner fields. JSON and
XML escape untrusted strings independently.

## Privilege boundary

Linux raw scans require `CAP_NET_RAW` or root. TCP Connect does not. The program
will refuse a raw scan with an actionable error when privileges are unavailable.
Privilege reduction after socket initialization will be evaluated before the raw
milestone is considered complete.
