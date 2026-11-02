# Validation results

Validated on 2026-11-02, including the `NetDriverSession` rename and the
`NetEvent`, `NetDecision`, and `NetStatus` protocol struct names. These naming
changes preserve the IOCTL layout and version.

Source: `C:\dev\test-pub\WfpFtpGuard` on DEV-11x64.
Deployment: `C:\dev\WfpFtpGuard-Poc` on W11Test.

## Build and unit tests

The CMake configure, Debug build, CTest run, and `sign-driver` target succeeded
under a non-elevated DEV-11x64 user token. Toolchain: Visual Studio 2022,
MSVC 19.44, x64, Windows SDK/WDK 10.0.26100.0. Compiler warnings are errors.

`guard-tests.exe` passed **3,649 assertions, zero failures** on both DEV-11x64
and W11Test after the naming changes.

OpenCppCoverage measured the following production files. Their implementations
were unchanged by the final naming changes.

| File | Covered executable lines | Line coverage |
| --- | ---: | ---: |
| `common/ftp_probe.hpp` | 66 / 66 | 100% |
| `common/secret_matcher.hpp` | 25 / 25 | 100% |
| `console/file_scanner.cpp` | 125 / 140 | 89.3% |

This is 216 / 231 measured lines (93.5%). Defensive native API failure paths
remain partly uncovered. These measurements do not claim coverage of the kernel
driver, loader, or ETW implementation; those components were exercised live.

## Live matrix

The final run completed all 15 cases on W11Test:

| Case | Expected and observed result |
| --- | --- |
| No open file | FTP allowed |
| Public file open | FTP allowed |
| Filename contains `secret` | FTP blocked |
| Content contains mixed-case `secret`, port 49237 | FTP blocked |
| UTF-16 LE content | FTP blocked |
| UTF-16 BE content | FTP blocked |
| Marker across a 64 KiB read boundary | FTP blocked |
| Fragmented command, public file | FTP allowed |
| Fragmented command, secret filename | FTP blocked |
| Secret file handle closed before connection | FTP allowed |
| IPv6, public file | FTP allowed |
| IPv6, secret filename | FTP blocked |
| HTTP on port 21, secret file open | HTTP allowed |
| FTP on port 21, secret file open | FTP blocked |
| ETW-only WinINet FTP client | Connection observed; driver absent |

The traffic clients also verified that inspection preserved their original
file-handle seek positions. The high-port and port-21 FTP server logs contained
zero received commands for the denied cases, confirming that the held command
was not forwarded before blocking.

Final console summaries:

```text
[DRIVER SUMMARY] ftp=13 blocked=8 allowed=5
[ETW SUMMARY] tcp_connections=14 wininet_ftp=0 correlated=14 wininet_events=0 wininet_connections=0
```

All 14 driver-observed connections, including the HTTP control case, correlated
with TCP/IP ETW by PID and the full connection tuple. Connection diagnostics
included the application image, full path, PID, session, endpoints, and flow ID.
Block diagnostics identified the matching filename and filename/content rule.

ETW-only mode observed TCP connection metadata, but the tested WinINet FTP client
emitted no FTP-specific WinINet event on this VM. Thus ETW-only operation cannot
be presented as generic FTP classification. Plaintext FTP confirmation came from
the driver's stream inspection; encrypted control traffic remains outside scope.

## Final state and evidence

Run directory on W11Test:
`C:\dev\tmp-scripts\wfp-live-20261102-120622`.
`wfp-live-state.json` and `wfp-final-verification.json` are in
`C:\dev\tmp-scripts`.

The console stopped normally. Final verification found no PoC driver service,
test fixture processes, or PoC ETW sessions. No certificate was imported into
W11Test's LocalMachine Root or TrustedPublisher stores, and no boot setting was
changed. The VM's existing test-signing configuration was used. The temporary
non-elevated build task on DEV-11x64 was removed after the final build.

SHA-256 of the tested `driver/WfpFtpGuard.sys`:

```text
8BB26F2D58780B1F482D067C920AAA544944D998A3E30266EFF64A9395F8B249
```

The binary package includes a per-file SHA-256 manifest. The checked-in-style
test harness is `tests/Invoke-LiveTests.ps1`; it is deliberately restricted to
W11Test and the documented lab paths. No Git commit or push was performed.
