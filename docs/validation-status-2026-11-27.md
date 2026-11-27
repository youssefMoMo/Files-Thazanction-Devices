# Windows Validation Record — 2026-11-27

This record captures results supplied by the project owner during the initial
Windows 11 Pro x64 development session. It is an evidence log, not a claim that
all runtime, security, or compatibility testing has passed.

## Confirmed local build and CLI observations

| Check | Owner-supplied result | Meaning |
|---|---|---|
| `cargo +1.100.0 build --locked --release` | `Finished release` in 33.48 seconds | The source present at that time compiled into a Release executable on the owner's Windows x64 machine. |
| Release EXE | `lan-transfer-core.exe`, 364,032 bytes | The file existed at `target\\release\\lan-transfer-core.exe`. |
| `lan-transfer-core.exe --help` | Help text displayed; exit code `0` | The particular EXE launched successfully before a later Code Integrity block was recorded. |
| `git diff --check` | No whitespace-error diagnostics; LF-to-CRLF warnings | No whitespace defect was shown. The warnings concern line-ending policy. |

## Checks blocked by local Application Control

| Check | Owner-supplied result | Meaning |
|---|---|---|
| `cargo +1.100.0 fmt --check` | Windows Application Control error 4551 while launching `cargo-fmt` | Formatting did not complete. |
| `cargo +1.100.0 clippy --locked --all-targets -- -D warnings` | `ring` build script was blocked with error 4551 | Clippy did not reach project lint analysis. |
| `cargo +1.100.0 test --locked --all-targets` | `ring` build script was blocked with error 4551 | No passing or failing test result is available from this run. |
| Later launch of `lan-transfer-core.exe receive ...` | Event 3077; process launch blocked | The app did not start and the listener was not opened during this attempt. |

## Authenticode and Code Integrity evidence

The owner supplied the following values for the blocked Release executable:

- `Get-AuthenticodeSignature`: `NotSigned`.
- Code Integrity Event ID: `3077`.
- Policy name: `VerifiedAndReputableDesktop`.
- Policy ID: `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`.
- Correlated Event ID: `3089`.
- `TotalSignatureCount=0`.
- `PublisherName=Unknown` and `IssuerName=Unknown`.
- `KnownRoot=0`.
- `SHA256 Flat Hash`: `0E226622458CE1792C2D24DD55C816DA3F7C78BDAD3024477BA82EDB0879CD94`.

The matching Authenticode and Code Integrity evidence establishes that the
specific EXE was unsigned and blocked by the active App Control policy. It does
not establish that the executable was corrupted or malicious. It also does
not mean an arbitrary code change can make an unsigned binary trusted: a
production-trusted signing identity and signed artifact are required.

## Transfer runtime evidence

The owner reported two sender attempts and one receiver log:

- One sender attempt stopped locally because the entered pairing code did not
  decode to 256 bits. No network connection was established by that attempt.
- Another sender attempt reported Windows socket error `10053`.
- The receiver accepted a connection and reported `10035` (`WouldBlock`) while
  entering the Noise handshake, then rejected the unauthenticated connection.

The source review traced this to the nonblocking listener's accepted socket
being passed into the handshake without explicitly restoring blocking mode.
The source bundle now calls `TcpStream::set_nonblocking(false)` in the shared
handshake socket configuration helper. A regression test covers that accept
path, and a loopback file-transfer test now checks the encrypted handshake,
streamed payload, SHA-256 validation, completion acknowledgement, and
no-overwrite behavior.

**Neither new test has been compiled or executed in this review environment.**
The subsequent attempted receiver launch was blocked before the application
started, so it did not validate or invalidate the socket fix. A successful
Windows CI run and a real local / two-PC transfer remain required.

## Trusted signing status

The repository contains a SignPath-based signed-release workflow. It requires
project-owner setup outside the source tree:

- acceptance/enrollment with a trusted signing provider;
- a production Authenticode signing policy/certificate;
- GitHub secret `SIGNPATH_API_TOKEN`;
- GitHub variables `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`, and
  `SIGNPATH_SIGNING_POLICY_SLUG`.

The workflow fails closed when these values are missing or signature
verification fails. This archive deliberately contains source and workflow
configuration only; it does not include the owner's unsigned local EXE, any
self-signed certificate, a private signing key, or a claim of a signed release.

## Required acceptance gates

1. Run Windows CI on the exact final commit: formatting, Clippy, unit tests,
   loopback transfer test, and Release build must all pass.
2. Complete trusted signing-provider enrollment and configure the GitHub
   secret/variables.
3. Run the signed-release workflow and verify `Get-AuthenticodeSignature`
   returns `Valid` for the downloaded EXE.
4. Test-launch that exact signed artifact on Windows 11 with Smart App Control
   On, then inspect Code Integrity events for new Event 3077 blocks.
5. Perform two-PC LAN transfers over the intended Wi-Fi/Ethernet networks and
   record SHA-256 equality on both endpoints.

No commit, push, release, signing request, or Windows VM test was performed
while preparing this source archive.
