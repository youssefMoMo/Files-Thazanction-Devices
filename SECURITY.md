# Security Policy

## Current status

This repository contains an early LAN transfer core. It is not yet a production security product and has not received an independent security audit.

## Reporting

Do not publish an unpatched vulnerability with working exploit details. Until a project security contact is configured, report issues privately to the repository owner through a private Git hosting security advisory mechanism. Do not include personal files or pairing codes in reports.

## Security design notes

- Pairing uses a fresh 256-bit random pre-shared key for each receive session. Temporary application-owned copies are wrapped with `zeroize`; this cannot guarantee removal of copies inside the OS, terminal, compiler-generated temporaries, or dependencies.
- Session traffic uses the Noise `NNpsk0_25519_ChaChaPoly_BLAKE2s` pattern through the `snow` crate.
- The first encrypted transport message confirms that both sides use the same PSK.
- Input frames and file chunks are bounded.
- File names are validated against path traversal and common Windows-invalid/reserved names.
- Files are written to a temporary file and checked with SHA-256 before finalization.
- Existing files are not intentionally overwritten.
- The application does not elevate privileges, install a service, disable antivirus, or add firewall exclusions.

## Known limitations

- No antivirus scanning is implemented.
- No Windows GUI, mDNS discovery, resumable transfer, or multi-file session yet.
- No persistent device identities or certificate pinning.
- No independent review of cryptographic protocol composition or filesystem race behavior.
- Legacy Windows compatibility is experimental and unverified.

## Smart App Control and release authenticity

The Windows release pipeline is designed to fail closed unless a trusted
code-signing provider has signed the release executable and the signature has
been verified. Do not bypass App Control policies or distribute unsigned
release executables as official builds. See `docs/smart-app-control.md` for
the exact behavior and configuration requirements.
