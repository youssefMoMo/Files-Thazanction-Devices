# Security Policy

## Current status

This repository contains an early LAN transfer core. It is not yet a production security product and has not received an independent security audit.

## Reporting

Do not publish an unpatched vulnerability with working exploit details. Until a project security contact is configured, report issues privately to the repository owner through a private Git hosting security advisory mechanism. Do not include personal files or pairing codes in reports.

## Security design notes

- Pairing uses a fresh 256-bit random pre-shared key for each receive session. Temporary application-owned copies are wrapped with `zeroize`; this cannot guarantee removal of copies inside the OS, terminal, compiler-generated temporaries, or dependencies.
- Session traffic uses the Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s` pattern through the `snow` crate.
- The first encrypted transport message confirms that both sides use the same PSK.
- Input frames and file chunks are bounded. The Noise handshake and encrypted pairing confirmation use a 12-second absolute deadline; this limits slow-trickle handshakes but does not eliminate LAN-level denial of service.
- File names are validated against path traversal and common Windows-invalid/reserved names.
- Files are written to a temporary file and checked with SHA-256 before finalization.
- Existing files are not intentionally overwritten.
- The application does not elevate privileges, install a service, disable antivirus, or add firewall exclusions.

## Known limitations

- No antivirus scanning is implemented.
- No Windows GUI, mDNS discovery, resumable transfer, or multi-file session yet.
- No persistent device identities or certificate pinning.
- No independent review of cryptographic protocol composition or filesystem race behavior.
- No destination free-space preflight, end-to-end failure-path test suite, or content-based file-type validation.
- Legacy Windows compatibility is experimental and unverified.

## Smart App Control and release authenticity

The Windows release pipeline is designed to fail closed unless a trusted
code-signing provider has signed the release executable and the signature has
been verified. The workflow is not operational until the repository owner
completes the external provider enrollment and GitHub secret/variable setup.
A regular CI build and this source archive are unsigned; do not treat either as
an official runnable Windows release. Do not bypass App Control policies or
distribute unsigned release executables as official builds. See
`docs/smart-app-control.md` for the exact behavior and configuration
requirements.

## Initial review record

See `docs/security-audit-initial-2026-11-27.md` for the source-level review findings and the validation steps still required. The project owner subsequently confirmed a successful Windows x64 Release build with Rust 1.100.0 on 2026-11-27 (`cargo +1.100.0 build --locked --release`; resulting EXE: 364,032 bytes). `cargo fmt --check` was blocked by Smart App Control while launching `cargo-fmt`; Clippy and tests were blocked before project checks because Smart App Control prevented the `ring` build script from executing. No successful formatting, Clippy, or test result is claimed. See the validation update in the initial audit report.
