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
| Unit tests | passed | 1 CTest target; checksum, invalid-input, timing and state checks passed |
| Address/undefined behavior sanitizers | passed | Same unit target passed with ASan and UBSan enabled |
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

The first successful CTest run reported one test target and zero failures. Network
behavior is still outside the tested scope.

A second build used `-fsanitize=address,undefined` and
`-fno-omit-frame-pointer`; its CTest run also reported zero failures. This covers
only the currently implemented foundation modules.
