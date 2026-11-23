# Contributing

1. Keep the project Rust-only for application logic.
2. Do not add unsafe code without a documented, reviewed platform requirement. The current crate forbids unsafe code.
3. Do not implement custom cryptographic primitives or invent a new handshake.
4. Add tests for every protocol, path-validation, or file-system behavior change.
5. Keep dependencies minimal and explain why a new dependency is needed.
6. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
7. Never add real pairing codes, personal files, certificates, private keys, or logs containing sensitive information.
8. Do not disable Windows Defender, SmartScreen, or Firewall to make tests pass.

9. Do not ask contributors to disable Smart App Control to run Cargo. On
   Windows 11 machines where Code Integrity blocks Cargo-generated build
   scripts, use the GitHub-hosted CI workflow. See
   `docs/smart-app-control.md`.
10. Do not publish unsigned Windows executables. Release builds must pass the
    trusted signing workflow and `scripts/Verify-Authenticode.ps1`.
