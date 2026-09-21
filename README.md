# ArgusScan

ArgusScan is an educational IPv4 network reconnaissance engine written in C. Its
goal is to expose packet construction, response correlation, scan semantics,
service probing and probabilistic operating-system fingerprinting instead of
delegating the core work to Nmap or another scanner.

> **Status:** TCP Connect milestone. The unprivileged IPv4 scanner accepts hostnames,
> port lists/ranges and timing profiles, and uses a bounded worker pool. Raw scans,
> service detection and OS fingerprinting are not implemented yet.

Use ArgusScan only against systems you own or have explicit permission to test.

## Planned scan types

- TCP Connect
- TCP SYN (half-open)
- TCP FIN, NULL and XMAS
- TCP ACK
- TCP Window
- UDP

The scan result model distinguishes `open`, `closed`, `filtered`,
`open|filtered` and `unfiltered`. Not every scan can produce every state; the
response matrix is specified in [Architecture](ARCHITECTURE.md).

## Platform scope

The raw-scanning engine targets Linux and IPv4 first. Development is hosted on
Windows 11 with WSL2 Ubuntu. Portable core modules are kept independent of raw
socket and packet-capture code. Windows-native raw scanning and IPv6 are not part
of the first release.

The planned capture backend is libpcap. Packet construction, checksums, response
correlation, state inference, service probes and fingerprint scoring remain
ArgusScan code.

## Build

The intended Linux build is:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

## Current usage

```sh
./build/argusscan \
  --scan tcp-connect \
  --ports 22,80,443,8000-8010 \
  --timing normal \
  127.0.0.1
```

TCP Connect completes a normal operating-system handshake. It is therefore easy
to observe in target logs, but does not require raw-socket privileges.

The foundation currently builds under WSL2 Ubuntu with GCC, and its unit checks
pass with warnings treated as errors. Exact observed versions and commands are
recorded in [Validation](docs/VALIDATION.md).

Raw scans will require either root or a narrowly scoped Linux capability:

```sh
sudo setcap cap_net_raw+ep ./build/argusscan
```

TCP Connect does not require raw-socket privileges.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Declared limitations](docs/LIMITATIONS.md)
- [Validation record](docs/VALIDATION.md)

The private portfolio review is intentionally stored outside this repository and
must not be published with the source tree.
