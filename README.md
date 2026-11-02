# WFP FTP Guard Windows proof of concept

This standalone CMake solution detects plaintext FTP control connections on any
TCP port. A WFP kernel callout holds the first recognized FTP command while an
elevated console examines the originating application's currently open disk-file
handles. It aborts the connection if a filename or raw file content contains
`secret`, ignoring ASCII case. UTF-8/ASCII and UTF-16 LE/BE content are covered.

The console prints a short application block for each connection, FTP evidence
without credentials or command arguments, the matched file and rule, and the
driver's resulting allow/block event. It starts the driver through SCM, installs
temporary WFP filters, and drains/unloads the driver on normal exit or Ctrl+C.

## Build

Use MSVC 2022 x64 and an installed Windows SDK/WDK. The default WDK is 10.0.26100.0;
override `WDK_ROOT` or `WDK_VERSION` at configuration if needed. No downloaded
libraries or NuGet packages are required.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug --parallel 4
ctest --test-dir build -C Debug --output-on-failure
cmake --build build --config Debug --target sign-driver
```

The driver is `build\driver\WfpFtpGuard.sys`. User programs are in `build\Debug`.
`sign-driver` creates a dedicated, non-exportable test-signing key in the build
user's certificate store and exports only its public `.cer`. An already
test-signing-enabled lab VM can load this embedded-signature driver without
installing the certificate into Root or TrustedPublisher. No trust-store or boot
configuration changes were needed on W11Test. Production signing is outside this
PoC.

```powershell
# Elevated console; scope the first run to the test client.
.\ftp-guard.exe --driver .\driver\WfpFtpGuard.sys --app .\ftp-traffic.exe
```

Omit `--app` to monitor all newly established outbound TCP connections. `--seconds
N` stops cleanly after N seconds, and `--no-etw` runs only the driver. Only one
console may own the driver. A forcibly terminated console cannot execute its SCM
cleanup; the device cleanup callback drains interception, but recovering the
service may require elevated `sc.exe stop WfpFtpGuardPoc` followed by
`sc.exe delete WfpFtpGuardPoc`.

## ETW without the driver

```powershell
.\ftp-guard.exe --etw-only --app .\ftp-traffic.exe --seconds 30
```

The console creates its own real-time TCP/IP system-trace session and a separate
WinINet provider session. It does not take over the existing NT Kernel Logger.
TCP connect events provide PID and IPv4/IPv6 endpoints on arbitrary ports, but
contain no application payload and are explicitly labeled candidates. WinINet
`InternetConnect` event 103 contains a service field: `FTP` identifies an FTP
session for applications using that API, including on nonstandard ports. Other
FTP stacks, such as libcurl, do not necessarily emit WinINet events.
This is best-effort telemetry: the WinINet FTP client tested on W11Test emitted
TCP connection events but no FTP-specific WinINet service event. ETW-only mode
therefore reports candidates on that system, rather than claiming to qualify
all FTP traffic. Driver stream inspection supplies the confirmed classification.

With the driver active, TCP/IP ETW events are correlated to WFP flow IDs using
PID, address family, both addresses and both ports in a bounded 30-second cache.
Correlation is reported regardless of which source arrives first. ETW-only mode
does not load the driver and does not enforce blocking. Event loss is reported
when a trace session stops.

## Controlled traffic

Run `ftp-traffic.exe --server --port 2121` in one console. It implements only the
small FTP handshake needed for tests, bound to loopback; it is not a file server.

```powershell
.\ftp-traffic.exe --port 2121 --file .\public.txt --expect allowed
.\ftp-traffic.exe --port 2121 --file .\secret-name.txt --expect blocked
.\ftp-traffic.exe --port 2121 --file .\public-with-sensitive-content.txt --expect blocked
.\ftp-traffic.exe --port 2121 --fragment --file .\public.txt --expect allowed
.\ftp-traffic.exe --port 2121 --wininet --expect allowed
```

`--ipv6` selects `::1` for both server and client. A separate `--server --http`
instance and `--http` client exercise non-FTP traffic, including on port 21.
`--close-file` closes the file before connecting. Clients also verify that the
inspector did not alter the original file handle's seek position.
Test clients linger for 1.5 seconds after their result so that their image details
remain queryable while ETW buffers flush.

`tests\Invoke-LiveTests.ps1` reproduces the 15-case lab matrix on W11Test, using
binaries in `C:\dev\WfpFtpGuard-Poc` and writing fixtures and logs beneath
`C:\dev\tmp-scripts`. Run it from an elevated PowerShell session and leave that
session open until it finishes. It verifies normal driver unload and exercises
ETW-only mode after the driver stops. See `TEST_RESULTS.md` for measured results.

## Implementation and boundaries

* ALE flow-established callouts capture the application PID and the connection
  tuple; stream callouts inspect reassembled application control headers, rather
  than guessing from IP/TCP headers or port 21. FTP is an application protocol.
* `USER`/`PASS` and other ambiguous commands require a valid `220` greeting.
  Distinctive commands such as `EPSV`, `PASV`, `SYST`, or `AUTH TLS` can identify
  an FTP attempt directly. Split greetings and commands are accumulated. This is
  a bounded protocol heuristic, not a complete FTP grammar or a cryptographic
  proof that a peer is an FTP server.
* Every tracked stream remains in out-of-band mode for its lifetime. Indications
  are cloned and absorbed, then reinjected in order after authorization. A
  recognized FTP command is not forwarded while the file check is pending.
* File enumeration uses dynamically resolved `NtQuerySystemInformation` with
  `SystemExtendedHandleInformation`, keeping full-width PIDs/handles. The older
  `GetHandles` example in this repository was inspected first, but its 16-bit
  handle layout and potentially blocking object-name queries are not reused.
  The native snapshot ABI is internal and can change with Windows versions.
* Duplicated file handles identify the actual open objects. Content is read
  through `ReOpenFile` with independent overlapped offsets; application seek
  positions are preserved. Process creation time is checked to prevent PID reuse
  from associating a flow with another process.
* Unreadable files, unsupported network-file content, scanner failures or an
  expired scan budget deny confirmed FTP conservatively. `inspection-incomplete`
  is reported separately from an actual secret match. Ordinary non-FTP traffic
  is not subjected to file scanning.
* Bounds: 64 simultaneously tracked flows, 256 KiB of queued stream data per
  flow, 512-byte initial control lines, a 3-second initial command window,
  8-second file-scan budget and 15-second driver decision timeout. Flows above
  the tracking capacity are not inspected; this is a lab PoC, not an enforcement
  guarantee under resource exhaustion.
* The file snapshot is taken when FTP is first recognized. Later file opens or
  changes are not continuously monitored. Raw content scanning does not unpack
  archives, parse document formats, or decrypt files. Plaintext FTP control is
  covered; implicit FTPS/TLS and standalone FTP data channels cannot be qualified
  from these control headers. Explicit `AUTH TLS` can be recognized before TLS.

## Microsoft references

The clone/absorb/reinject design follows Microsoft's
[stream editing sample](https://github.com/microsoft/Windows-driver-samples/tree/main/network/trans/stmedit)
and [stream inspection contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/stream-inspection).
See also [FwpsCloneStreamData0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsclonestreamdata0),
[FwpsStreamInjectAsync0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsstreaminjectasync0),
[system ETW sessions](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session),
and [ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).
