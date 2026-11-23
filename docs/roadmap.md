# Roadmap after v0.1 core

## v0.2 — Windows desktop shell

- Native Win32 controls and file picker.
- Non-blocking UI event loop; transfer work stays off the UI thread.
- Receive approval dialog and transfer progress.
- Settings and local transfer history.

## v0.3 — Network usability

- mDNS device discovery with an IP-entry fallback.
- Better interface selection (Wi-Fi/Ethernet) and private-network guidance.
- Multi-file queue and cancel support.
- Resume protocol design with authenticated chunk offsets and file identity.

## v0.4 — Security hardening

- Defender / installed-antivirus scanning integration where supported and permitted.
- Stronger validation based on file signatures and archive metadata.
- Fuzzing of all protocol parsers.
- External cryptographic and filesystem security review.
- Persistent device identity and revocation model.

## v0.5 — Adaptive resources

- CPU, available RAM, disk throughput and network throughput measurements.
- Bounded queue and backpressure tuning.
- Low / Balanced / High profiles.
- Benchmarks on low-end hardware.

## Release gate

No version should be called production-ready until it passes Windows-version-specific runtime tests, independent security review, large-file and failure-mode testing, and signed reproducible release builds.


## Current prototype status (2026-11-23)

Implemented in the initial source drop: synchronous TCP LAN transfer, Noise PSK encryption, one-time pairing code, interactive receiver consent, streaming one-file transfer, SHA-256 verification, extension allow-list, and no-overwrite destination handling.

Not implemented: Win32 graphical UI, mDNS discovery, antivirus/Defender integration, adaptive resource controller, multi-file queues, resume, installer/signing, and validated Windows 8/8.1 builds. Do not market this prototype as complete or production-ready.
