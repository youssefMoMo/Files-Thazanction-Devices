# Initial Security Review — 2026-11-27

## Scope and confidence

This is a source-level review of the supplied ZIP snapshot, focused on `src/pairing.rs`, `src/protocol.rs`, `src/transfer.rs`, `src/main.rs`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `README.md`, `SECURITY.md`, and the architecture / Windows compatibility documents.

The supplied archive has no `.git` directory and does not contain `LAN-Transfer-Core.md`, `.github/workflows/`, or any integration-test source files. The separate project brief supplied with the task was used as the requirements reference. The source bundle contains `target/` build artifacts, which are not source-of-truth evidence that the current source compiles or tests pass.

No Rust toolchain (`rustc`, `cargo`, `rustfmt`, `clippy`, or `rustup`) is installed in the review environment. Therefore, no build, unit test, formatter, Clippy, dependency audit, fuzz test, or Windows runtime test is claimed as passing. Findings marked **patched locally** are code changes that still require those checks.

This is not an independent cryptographic audit and is not a production security approval.

## Severity summary

| Severity | Confirmed findings | State |
|---|---:|---|
| Critical | 0 | None identified in this static pass |
| High | 0 | None confirmed in this static pass |
| Medium | 8 | 4 locally patched; 4 remain open |
| Low | 2 | Follow-up / validation work |

Severity is based on the current CLI prototype and its LAN-only, user-consented transfer model. It must be reassessed as the application gains a GUI, discovery, background operation, and multi-session support.

## Findings

### MED-01 — Handshake could be kept open by a slow-trickle peer

**Affected:** `src/protocol.rs`, `src/transfer.rs`

The previous handshake path relied on TCP socket read/write timeouts. Those timeouts apply to individual blocking operations, so a peer able to deliver a few bytes before each idle timeout could keep a partial frame alive much longer than the intended pairing window.

**Local change:** Added a 12-second absolute deadline shared by the Noise handshake and encrypted PSK-confirmation messages. Deadline-aware read/write helpers recalculate the remaining time for every socket operation. The receiver also rejects a pairing that completes after the five-minute pairing deadline.

**Regression test added:** `handshake_frame_reader_enforces_an_absolute_deadline` simulates a peer that trickles a frame header/body across the deadline.

**State:** Patched locally; uncompiled and unexecuted in this environment.

### MED-02 — Pairing-code text copies had a longer-than-needed lifetime

**Affected:** `src/pairing.rs`, `src/transfer.rs`

The input string returned by `rpassword` and the formatted display code were ordinary `String` values. They could remain in application-owned memory after the secret had already been decoded or displayed.

**Local change:** The input code is wrapped in `Zeroizing<String>` and dropped immediately after decoding. `PairingSecret::to_code` now returns `Zeroizing<String>`, and the receiver drops the display value immediately after printing it.

**Caveat:** This does not promise erasure of copies held by terminal APIs, formatting internals, the operating system, allocator behavior, or dependencies. `PairingSecret` is still `Clone`, so every clone must be accounted for by its caller.

**State:** Patched locally; not runtime-verified.

### MED-03 — Windows reserved device-name validation missed special aliases

**Affected:** `src/transfer.rs`

The original reserved-name checks covered common DOS device names and `COM1`–`COM9` / `LPT1`–`LPT9`, but did not cover `CONIN$`, `CONOUT$`, or the superscript forms `COM¹`–`COM³` and `LPT¹`–`LPT³`.

**Local change:** Added those aliases to the validator and regression cases for `CONIN$.jpg`, `COM1.png`, and `LPT³.zip`.

**State:** Patched locally; Windows filesystem behavior still needs testing on supported Windows versions.

### MED-04 — No destination free-space preflight or reservation

**Affected:** `src/transfer.rs`

The receiver enforces a declared-size ceiling of 512 GiB, but does not check available space before accepting a transfer. A user may approve a file that fills the destination volume and causes unrelated writes to fail. The sender-provided size is metadata, not a reservation.

**Recommendation:** Add a Windows-specific available-space query behind a small platform abstraction, re-check immediately before transfer, and report that free-space checks are advisory because another process can consume space concurrently. Keep the bounded streaming path; do not allocate the full file.

**State:** Open.

### MED-05 — The global invalid-connection budget permits LAN denial of service

**Affected:** `src/transfer.rs`

The receiver ends its pairing session after eight rejected connections. Any host able to reach the listener can consume this global budget without knowing the pairing code. The absolute handshake deadline limits per-connection occupation, but does not prevent a LAN peer from using the full budget.

**Recommendation:** Revisit the lockout policy before multi-device discovery. Consider per-peer rate limits, bounded backoff, and explicit user-visible cancellation / restart. Do not remove brute-force controls without a threat-model review.

**State:** Open; current behavior is documented as a LAN denial-of-service limitation.

### MED-06 — Extension allow-list is not content validation or malware scanning

**Affected:** `src/transfer.rs`, `SECURITY.md`, `README.md`

The allow-list checks only the filename extension. It does not inspect file signatures or parse ZIP/image/video formats. No Microsoft Defender or other antivirus scan is implemented. An attacker can therefore send arbitrary bytes with an allowed extension; SHA-256 confirms transfer integrity, not benign content.

**Recommendation:** Keep the UI wording explicit (`Not Scanned` until a real supported scan completes). Design Defender integration around documented Windows interfaces and honest states. Never treat a matching hash, extension, or successful Noise session as a malware verdict.

**State:** Open and disclosed in project documentation.

### MED-07 — No end-to-end failure-path coverage

**Affected:** tests / transfer orchestration

The original snapshot had inline unit tests for pairing, basic protocol behavior, extensions, names, and LAN address filtering, but no end-to-end file-transfer test. The final source bundle adds a loopback transfer regression test that exercises a multi-chunk encrypted transfer, SHA-256 verification, completion acknowledgement, and destination collision handling. Disconnect cleanup, digest mismatch, full disk, cancellation, and multi-gigabyte file tests are still missing.

**Recommendation:** Extend loopback coverage with fault-injecting peers and failure paths. Keep Windows-specific filesystem and large-file tests in Windows CI, then repeat device-to-device tests on real LAN hardware.

**State:** Partially addressed in source; all added tests still require Windows CI execution.

### MED-08 — Accepted sockets could remain nonblocking during the Noise handshake

**Affected:** `src/transfer.rs`, `src/protocol.rs`

The receiver sets its listening `TcpListener` to nonblocking mode so it can poll until the five-minute pairing deadline. It then passed accepted `TcpStream` values directly into the handshake path without explicitly normalizing their blocking mode. On Windows, the observed accepted stream returned `WSAEWOULDBLOCK` (10035) during the first handshake read. The receiver counted this as an unauthenticated attempt; the sender subsequently observed the connection abort (10053).

**Local change:** `set_handshake_timeouts` calls `TcpStream::set_nonblocking(false)` before applying read/write timeouts. This centralizes the invariant for both accepted and outgoing streams. Added `accepted_socket_from_nonblocking_listener_completes_handshake`, which reproduces the receiver's nonblocking-listener accept path and verifies a complete authenticated exchange. The final source bundle also adds `loopback_transfer_verifies_content_and_never_overwrites_existing_file`, covering an authenticated loopback session, multi-chunk file transfer, SHA-256 validation, completion acknowledgement, and preservation of an existing destination file.

**Runtime evidence:** On 2026-11-27, the project owner reported a loopback attempt where the receiver logged `WouldBlock` / Windows error 10035 and then rejected the session; the sender reported error 10053. This is consistent with the source-level issue above.

**State:** Included in the final source bundle with regression tests; not yet compiled or executed in this review environment. The owner's later launch attempt was blocked by Smart App Control before the application started, so the socket fix remains runtime-unverified.

### LOW-01 — Dependency pin review should include the latest `rpassword` bugfix

**Affected:** `Cargo.toml`, `Cargo.lock`

The project pins `rpassword = 7.5.4`. Upstream has released 7.5.5 as a bugfix for restoring terminal configuration after SIGINT. This review did not update the lockfile because Cargo is unavailable here; dependency changes must be resolved and validated by Cargo rather than edited manually.

**Recommendation:** Evaluate `rpassword` 7.5.5 in the next dependency-refresh change, inspect its transitive Windows dependencies and MSRV, regenerate `Cargo.lock` with Rust 1.100.0, and run the full locked CI suite.

**State:** Follow-up; not represented as a known exploitable vulnerability in this project.

### LOW-02 — Windows 8 / 8.1 support remains unverified

**Affected:** `rust-toolchain.toml`, Windows compatibility policy, release pipeline

The standard `x86_64-pc-windows-msvc` target is not proof of Windows 8 compatibility. The special Win7-compatible MSVC target is Tier 3 and has weaker build/test guarantees. No actual Windows 8 or 8.1 runtime evidence is present in the supplied source bundle.

**Recommendation:** Maintain a separate experimental legacy build. Confirm target availability and standard-library build requirements for the exact Rust 1.100.0 toolchain, inspect imported APIs and dependency minimum OS versions, then run the complete test matrix on clean Windows 8 and Windows 8.1 Update VMs. Do not advertise compatibility beforehand.

**State:** Open; current documentation correctly describes legacy compatibility as experimental.

## Verified implementation characteristics in this source snapshot

- Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s` through `snow`; this is not TLS.
- 256-bit random, session-scoped pairing PSK.
- First encrypted transport messages confirm possession of the PSK.
- TCP framing is bounded; transfer chunks are 32 KiB.
- File payloads are streamed rather than loaded entirely into memory.
- SHA-256 is checked before finalization.
- Receiver approval is required before file data is accepted.
- Temporary files use `create_new`; final commit uses a no-overwrite hard link.
- No automatic launch, Windows service, administrator elevation, Defender disablement, or broad firewall exception is present in the inspected source.

These are source-code observations, not proof of successful runtime behavior on Windows.

## GitHub / CI reconciliation

The public repository and Actions pages were reloaded and rechecked on 2026-11-27. The default branch shown is `main`; the latest visible commit is `69edeec` (`Fix unused imports and secure pairing code input`). The Actions page lists four Rust CI runs: runs #1–#3 failed, while `Rust CI #4` for `69edeec` reports **Success**, with a total duration of 1m 11s and a successful `test` job of 1m 8s. The public run summary does not expose detailed logs without sign-in, and no build artifact is listed for that run.

The CI workflow visible in the repository defines these checks on `windows-latest`: `cargo +1.100.0 fmt --check`, Clippy with `--locked --all-targets -- -D warnings`, tests with `--locked --all-targets`, and a locked release build. Therefore, the latest upstream baseline has a successful hosted CI result. This success applies to commit `69edeec`, **not** to the local security changes in this review.

The uploaded ZIP is not a Git checkout and has no `.git` metadata. It does not include `.github/workflows/` or the separately named `LAN-Transfer-Core.md`; the pasted project brief was available and used as the requirements reference. The public repository does include both workflow files. The uploaded core-source line counts match the GitHub `69edeec` pages for the three reviewed modules (`transfer.rs` 520 lines, `protocol.rs` 199 lines, `pairing.rs` 67 lines), and spot-checked code sections agree. Exact byte-for-byte hashes were not compared, so the ZIP is not declared a cryptographic or exact-tree match to the remote commit. Before applying a patch, restore the missing workflow files from the intended `main` checkout rather than replacing the full repository with the ZIP snapshot.

The separate signed-release workflow is present in the repository, but the latest run inspected is Rust CI rather than a signed release. No signed release artifact or completed SignPath signing operation was verified in this review.

## Validation update from the project owner — 2026-11-27

The project owner ran the following commands on the Windows x64 development machine after the local review changes were present:

| Command | Observed result | Interpretation |
|---|---|---|
| `git diff --check` | No whitespace-error diagnostics; Git emitted LF-to-CRLF conversion warnings for seven tracked files | No whitespace defect was reported in the displayed output. The PowerShell `$LASTEXITCODE` was not captured, so the process exit code is not independently recorded. |
| `cargo +1.100.0 fmt --check` | Blocked launching `cargo-fmt` with Windows Application Control error 4551 | Formatting check did not run to completion. |
| `cargo +1.100.0 clippy --locked --all-targets -- -D warnings` | `ring` build script was blocked before execution with error 4551 | Clippy did not reach project lint analysis. |
| `cargo +1.100.0 test --locked --all-targets` | `ring` build script was blocked before execution with error 4551 | Tests did not run to completion; no test result is claimed. |
| `cargo +1.100.0 build --locked --release` | `Finished release` in 33.48 seconds | Release compilation succeeded on the reported Windows x64 toolchain. |

The resulting `target\release\lan-transfer-core.exe` was present, with a reported size of 364,032 bytes and last-write time of 2026-11-27 13:52:34. This confirms successful creation of the Release executable, not successful runtime transfer behavior, Authenticode signing, or Smart App Control acceptance of the resulting EXE.

`git diff --stat` reported seven tracked files (226 insertions and 42 deletions). The new audit report itself is untracked, so Git excludes it from that statistic. The `git apply --check` attempt did not inspect patch contents: it failed because `LAN-Transfer-Core-initial-security-review.patch` was not present at the referenced path. The working-tree file list matches the seven tracked paths plus the untracked audit report from the prepared review change set; do not apply the patch again without first inspecting the current diff.

The line-ending warnings are not, by themselves, evidence of a source-code error. Do not normalize all files or change `core.autocrlf` blindly; inspect `.gitattributes` and the effective Git configuration before making a repository-wide line-ending policy change.

## Required next gate

1. Run the `Rust CI` workflow on the exact final source revision.
2. Require `cargo +1.100.0 fmt --check` to pass.
3. Require `cargo +1.100.0 clippy --locked --all-targets -- -D warnings` to pass.
4. Require `cargo +1.100.0 test --locked --all-targets` to pass, including the new socket and full-transfer regression tests.
5. Require `cargo +1.100.0 build --locked --release` to pass on Windows x64.
6. Complete trusted signing-provider enrollment, sign the executable, and verify Authenticode before distributing a binary.
7. Perform two-machine LAN transfer tests, including the failure cases listed above.
8. Review the Windows 8/8.1 legacy target separately; do not treat the standard Windows 10+ target as evidence.

No commit, push, release, or signing operation was performed as part of this review.


## Final bundle additions — 2026-11-27

The source package now restores the repository's two GitHub Actions workflows,
adds a manual `workflow_dispatch` path to the signed workflow (restricted to
`main` or a version tag), and runs Clippy as part of the signed build gate. The
normal CI workflow runs format, Clippy, tests, and Release build on a
GitHub-hosted Windows runner. `.gitattributes` fixes stable LF line endings for
source and documentation files.

The owner later supplied correlated Code Integrity Event 3077 / 3089 records
for the Release EXE. Event 3089 reports `TotalSignatureCount=0`,
`PublisherName=Unknown`, `IssuerName=Unknown`, and `KnownRoot=0`; the recorded
SHA-256 flat hash matches the owner's PowerShell SHA-256 hash. This confirms
that the blocked EXE had no embedded Authenticode signature. The source bundle
cannot create a production-trusted signing certificate or activate SignPath
without the project owner's external enrollment, certificate/policy, and
GitHub secret/variable configuration. The signed workflow fails closed until
that configuration is present.

See `docs/validation-status-2026-11-27.md` for the complete owner-supplied
Windows observations and the remaining release acceptance gates.
