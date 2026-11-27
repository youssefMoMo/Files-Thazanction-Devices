# Smart App Control compatibility

## What happened on the development PC

The Code Integrity event supplied during development contains policy ID
`{0283ac0f-fff1-49ae-ada1-8a933130cad6}`. Microsoft identifies this as the
`VerifiedAndReputableDesktop` base policy used when Smart App Control is On.
The earlier blocked files included Cargo-generated build-script executables under
`target\debug\build\...\out\build_script_build.exe`. A later attempt to
launch `target\release\lan-transfer-core.exe` was also blocked before the
application started.

The correlated Code Integrity events for that Release executable reported
`TotalSignatureCount=0`, `PublisherName=Unknown`, `IssuerName=Unknown`, and
`KnownRoot=0`. `Get-AuthenticodeSignature` reported `NotSigned`. The SHA-256
flat hash recorded by Code Integrity matched the PowerShell hash supplied by
the project owner. This confirms that this exact binary had no embedded
Authenticode signature; it does not indicate that the executable was corrupted.

This is not evidence that those Rust crates are malware. Cargo compiles each
crate's `build.rs` into an executable and runs it during the build. Smart App
Control evaluates executables and other code at process/load time; unsigned,
unknown code can be blocked. Signing the final application executable does not
retroactively sign those short-lived Cargo build tools.

## Project policy

- Never ask users or contributors to turn off Smart App Control, Defender,
  SmartScreen, or Code Integrity.
- Never add broad App Control, antivirus, or Firewall exclusions.
- Do not describe self-signed certificates as production-trusted.
- Build and test in GitHub-hosted Windows CI for contributors whose local
  Smart App Control policy blocks Cargo-generated build scripts.
- Only publish a Windows release after a trusted signing service has signed the
  executable and the release workflow has verified its Authenticode signature.
- Sign every executable component shipped with the application. When an
  installer, updater, DLL, helper executable, or uninstaller is added, include
  it in the signing artifact configuration and signature-verification step.

## Release signing

The repository includes `.github/workflows/ci.yml` and
`.github/workflows/signed-release.yml`. CI builds and tests the source on a
GitHub-hosted Windows runner. The signed-release workflow builds and tests
again, uploads the unsigned executable to the trusted signing service, verifies
the returned Authenticode signature, and only then creates a downloadable ZIP
artifact. The workflow fails closed: it does not publish an unsigned release
if signing is not configured or the signature is invalid. It can be started by
pushing a `vMAJOR.MINOR.PATCH` tag or manually from the GitHub Actions page on
`main` (or a version tag).

### SignPath setup required by the repository owner

Signing is not active until the project owner completes these external setup
steps:

1. Apply to SignPath Foundation's open-source signing program and receive
   approval. Eligibility is determined by SignPath; this repository is not
   enrolled automatically by adding a workflow file.
2. Create a SignPath project connected to the public GitHub repository.
3. Add the predefined `GitHub.com` trusted build system and link it to the
   project. Install the SignPath GitHub App if required for origin verification.
4. Create a release signing policy using a production Authenticode certificate
   that is trusted for Windows Smart App Control.
5. Configure the default artifact configuration to sign the single
   `lan-transfer-core.exe` file using Authenticode. If future packages contain
   additional executable files, update the configuration to sign all of them.
6. Add the following GitHub repository settings:

   **Secret**
   - `SIGNPATH_API_TOKEN`

   **Variables**
   - `SIGNPATH_ORGANIZATION_ID`
   - `SIGNPATH_PROJECT_SLUG`
   - `SIGNPATH_SIGNING_POLICY_SLUG`

7. After the SignPath configuration has been validated, push a version tag
   such as `v0.1.0`, or open GitHub Actions → Signed Windows Release → Run
   workflow while selecting `main` (or a valid version tag).

Until these external steps are completed, the signed workflow intentionally
fails at its configuration gate. A source ZIP, a locally built EXE, a GitHub
CI artifact, or a self-signed certificate is not a substitute for the
production-signed Windows executable. The workflow configuration alone cannot
enroll the repository or create a trusted signing identity.

SignPath's GitHub integration verifies that artifacts originate from a GitHub
workflow and that open-source signing jobs use GitHub-hosted runners. The
signing request may require manual approval according to the foundation's
policy.

If SignPath does not accept the project, configure another production code
signing provider whose certificate chains to a CA in Microsoft's Trusted Root
Program, then adapt the release workflow to that provider. A local self-signed
certificate is for controlled testing only and is not a public Smart App
Control compatibility solution.

## Important limitation for local Rust development

There is no Cargo.toml switch that makes dynamically generated build scripts
trusted by Smart App Control. A regular `cargo check` may still be blocked on
this specific Windows 11 machine because Cargo must execute unsigned build
script binaries and may load unsigned procedural-macro DLLs while compiling.
The final application's signature cannot solve this earlier compiler-stage
problem.

For this machine, use the GitHub-hosted build workflow and download the signed
release artifact only after the repository owner has completed the trusted
signing-provider setup. The ordinary CI job produces an unsigned build for
validation; it is not intended to be launched on a Smart App Control-enforced
PC. If the signing provider is not configured, no runnable signed artifact is
available yet. If interactive local compilation is required, use a separate
supported development environment rather than lowering protection on the
primary PC. Do not copy unsigned `target` executables from CI to a Smart App
Control-enforced PC.

## What signing guarantees—and what it does not

Microsoft documents that when its app-intelligence service cannot make a
safety prediction, Smart App Control allows code signed with a certificate
issued by a CA in the Microsoft Trusted Root Program. This is the supported
compatibility path for distributed application binaries.

A valid signature proves publisher identity and that the signed file has not
changed since signing. It does not guarantee that Microsoft will never block
an artifact identified as malicious, that every policy on every PC behaves the
same way, or that a newly published file has SmartScreen reputation. Releases
must still be tested on a Windows 11 machine with Smart App Control On.

## Verification on a test PC

After downloading a signed release, run:

```powershell
Get-AuthenticodeSignature .\lan-transfer-core.exe | Format-List Status, StatusMessage, SignerCertificate
```

The status must be `Valid`. Then test-launch the exact downloaded artifact on
a clean Windows 11 test machine with Smart App Control On, and review
`Microsoft-Windows-CodeIntegrity/Operational` for new event 3077 entries.
The project does not change the user's Windows security configuration.

Read-only diagnostics are also available:

```powershell
.\scripts\Show-SmartAppControlStatus.ps1
```
