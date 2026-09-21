# ArgusScan architecture

## Design goals

ArgusScan is small enough to explain from packet bytes to final JSON. It uses
bounded queues, bounded input, explicit deadlines and a fixed worker pool. Raw
packet transmission is event-driven; it is not implemented as one thread per port.

## Planned data flow

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

## Privilege boundary

Linux raw scans require `CAP_NET_RAW` or root. TCP Connect does not. The program
will refuse a raw scan with an actionable error when privileges are unavailable.
Privilege reduction after socket initialization will be evaluated before the raw
milestone is considered complete.

