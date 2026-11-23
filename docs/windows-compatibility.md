# Windows Compatibility Policy

## Stable compiler baseline

The repository pins the stable Rust compiler to `1.100.0`. Current official `*-pc-windows-msvc` Rust targets require Windows 10 or newer. Therefore, compiling this project for `x86_64-pc-windows-msvc` does **not** establish Windows 8 compatibility.

## Legacy target path

Rust documents Tier 3 targets `i686-win7-windows-msvc` and `x86_64-win7-windows-msvc`. These targets are intended to continue Windows 7 compatibility, but Rust does not distribute prebuilt standard-library artifacts for them. Building requires building the standard library from source (for example with nightly `-Z build-std`) or building a custom Rust toolchain. Tier 3 does not provide the same automated build/test guarantees as Tier 1.

An experimental x64 build attempt may look like this on a supported build host:

```powershell
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly build -Z build-std=std,panic_unwind --target x86_64-win7-windows-msvc --release
```

This command uses a nightly compiler and is **not** a reproducible Rust 1.100.0 stable build. It is an experiment, not a supported release pipeline. It may fail because of toolchain or dependency compatibility. Do not distribute its output as a supported Windows 8 build without runtime testing.

## Required validation before claiming Windows 8/8.1 support

- Build the exact release artifact using the intended legacy target.
- Run it on clean Windows 8 and Windows 8.1 Update x64 virtual machines.
- Confirm all imported Windows APIs exist on those systems.
- Run pairing, wrong-code rejection, receive consent, large-file transfer, disk-full, cancel, and interrupted-transfer tests.
- Test Windows Firewall behavior without disabling Defender or adding broad exclusions.
- Check every dependency's minimum OS requirements, including transitive dependencies.
- Re-run these tests for every release.

## Security status of old Windows versions

Windows 8.1 stopped receiving security updates on 10 January 2023. Windows 8 reached end of support earlier. A transfer application cannot compensate for an unpatched operating system. Use a supported Windows release for sensitive transfers whenever possible.
