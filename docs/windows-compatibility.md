# Windows Compatibility Policy

## Stable compiler baseline

The repository pins the stable Rust compiler to `1.100.0`. Current official `*-pc-windows-msvc` Rust targets require Windows 10 or newer. Therefore, compiling this project for `x86_64-pc-windows-msvc` does **not** establish Windows 8 compatibility. See the [official Rust MSVC target requirements](https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html).

## Legacy target path

The current Rust platform table lists `i686-win7-windows-msvc` and `x86_64-win7-windows-msvc` as Tier 3 targets intended for Windows 7 compatibility. Rust's Tier 3 policy explicitly states that these targets are not built or tested automatically and that official builds are unavailable. The table marks standard-library source support, but that is not the same as a prebuilt `rust-std` component distributed by rustup. Building therefore requires building the standard library from source (for example with nightly `-Z build-std`) or creating a custom Rust toolchain. Tier 3 does not provide the same automated build/test guarantees as Tier 1. See the [Rust platform support table and Tier 3 policy](https://doc.rust-lang.org/stable/rustc/platform-support.html).

The exact availability and build path of this target with the pinned Rust `1.100.0` toolchain have **not** been confirmed in this project yet. Verify it on a clean Windows build host before designing the legacy release pipeline.

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

Windows 8 reached end of support on 13 January 2016, and Windows 8.1 reached end of support on 10 January 2023. Neither receives normal Windows security updates. A transfer application cannot compensate for an unpatched operating system. Use a supported Windows release for sensitive transfers whenever possible. See the [Microsoft Windows 8 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-8) and [Windows 8.1 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-81).
