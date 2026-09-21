# Validation record

This file records observed checks. Planned checks are not presented as passing.

## Environment discovered on 2026-09-21

- Host: Windows 11
- Linux environment: WSL2, Ubuntu 26.04 LTS
- WSL kernel observed: 6.18.33.2-microsoft-standard-WSL2
- C compiler in Windows PATH: not found
- WSL compiler: GCC 15.2.0
- WSL CMake: 4.2.3
- WSL libpcap: 1.10.6 development package

## Current validation status

| Check | Status | Evidence |
| --- | --- | --- |
| Source and documentation structure | reviewed locally | Files created in isolated ArgusScan tree |
| CMake configure | passed | Debug build generated under WSL2 |
| Compilation with warnings as errors | passed | GCC 15.2.0 compiled all foundation targets |
| Unit and loopback tests | passed | 1 CTest target; checksums, port parser, timing, pool, open/closed TCP and invalid inputs passed |
| Address/undefined behavior sanitizers | passed | Expanded CTest target passed with ASan and UBSan enabled |
| TCP Connect CLI | passed | Loopback ports 1 and 65535 were reported closed in the observed run |
| Packet construction/parsing | passed | TCP and UDP round trips validated IP and pseudo-header checksums; malformed options rejected |
| libpcap link-layer parsing | passed | Ethernet, VLAN, Linux cooked and raw offsets covered by unit checks |
| Raw privilege handling | passed | Unprivileged run returned EPERM guidance; WSL root opened the raw socket |
| SYN | passed in loopback lab | Open listener reported open with fingerprint; adjacent closed port reported closed |
| FIN / NULL / XMAS | passed in loopback lab | Open listener reported open\|filtered after retries; closed port returned RST |
| ACK | passed in loopback lab | Both reachable ports reported unfiltered after RST |
| Window | behavior observed | Linux loopback returned zero-window RST for both; both were classified closed, demonstrating the heuristic limitation |
| UDP | passed in loopback lab | Replying UDP listener reported open; adjacent closed port reported closed from ICMP |
| Service detection | passed in loopback lab | SSH greeting on nonstandard port 18080 was recognized by content and safely escaped |
| JSON output | passed | PowerShell `ConvertFrom-Json` parsed TCP Connect and raw SYN output |
| XML output | passed | PowerShell loaded output as XML with `argusscan` root and expected port count |
| Target expansion | passed | Unit checks covered `/30`, last-octet range, hostname and over-limit rejection; CLI scanned `127.0.0.1-2` |
| Parallel TCP raw deadlines | passed in loopback lab | Two silent open FIN/NULL/XMAS ports completed together at about 3.0 s, not serially at about 6.0 s |

## Installed Linux packages

The development environment was prepared with:

```sh
sudo apt update
sudo apt install build-essential cmake pkg-config libpcap-dev
```

The packages were installed inside the WSL Ubuntu distribution, not on the Windows
host. No raw-socket capability has been assigned to the binary.

## Commands observed passing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/argusscan --version
./build/argusscan --help
```

The current CTest target reported zero failures. Its TCP integration creates a real
ephemeral loopback listener, observes that port as open, closes it and observes the
same port as closed. A separate CLI smoke run scanned loopback ports 1 and 65535 and
reported both closed.

A second build used `-fsanitize=address,undefined` and
`-fno-omit-frame-pointer`; its expanded CTest run also reported zero failures. This
covers pure parsers, builders, format helpers, service matching, TCP Connect and
thread-pool checks. The privileged live smoke is separate from the sanitizer run.
Filtered-network behavior has not yet been reproduced in a controlled firewall test.

## Privileged loopback smoke

`scripts/raw-loopback-smoke.sh` starts two controlled TCP listeners and one UDP
listener, verifies that all remain alive, and exercises all raw scan types. The
observed open TCP ports were 18080 and 18082; 18081 was closed. FIN, NULL and XMAS
each took about three seconds total for both open/filtered ports because the normal
profile schedules them concurrently and performs the initial probe plus two retries.
