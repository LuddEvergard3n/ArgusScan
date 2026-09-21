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
| Raw socket integration | pending | Raw scanning is not implemented |
| libpcap capture | pending | Dependency is installed; capture code is not implemented |

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
`-fno-omit-frame-pointer`; its CTest run also reported zero failures. This covers
the implemented core and TCP Connect modules. Filtered-network behavior has not yet
been reproduced in a controlled firewall test.
