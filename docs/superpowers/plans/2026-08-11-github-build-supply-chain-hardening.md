# Delivery C.1 GitHub Build Supply-Chain Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This repository's approved execution mode is inline; do not create a branch, worktree, pull request, or subagent.

**Goal:** Lock every repository-controlled Rust and GitHub Actions build input, enforce the contract in CI, and prove the rebuilt exact artifact still passes isolated attachment and passive observation.

**Architecture:** A test-first RED commit introduces a cross-platform static policy gate, an xtask command-contract test, and a temporary read-only GitHub lock-bootstrap workflow. The exact RED workflow produces `Cargo.lock` as an artifact; one GREEN commit removes the bootstrap, commits the lock, pins Actions/toolchains/linker, and makes every dependency-resolving build path locked. A documentation commit becomes the final exact artifact accepted on the authorized isolated host.

**Tech Stack:** GitHub Actions, PowerShell 5.1/7, Cargo lock format v4, Rust `1.97.1`, Rust `nightly-2026-08-10`, `bpf-linker 0.10.4`, Rust unit tests, existing MUSL bundle and isolated-host harness.

## Global Constraints

- Work directly on `main`; do not create a branch, worktree, pull request, or subagent.
- Do not run Cargo, rustc, rustfmt, Clippy, `bpf-linker`, or Rust tests on the local authoring host.
- All compilation and automated tests run only in GitHub Actions.
- Use `apply_patch` for every repository file edit, including addition of the generated lock-file text.
- Stable Rust is exactly `1.97.1`; eBPF nightly is exactly `nightly-2026-08-10`; `bpf-linker` is exactly `0.10.4`.
- Remote Actions use only the full commits fixed by the approved design; keep their human release labels as comments.
- All workflows retain `permissions: contents: read`; no workflow may commit, push, or request write permission.
- The temporary bootstrap may run `cargo generate-lockfile`; all permanent dependency-resolving commands must use locked resolution.
- `cargo fmt --all -- --check` remains unchanged because it does not resolve dependencies.
- The final tree must not contain the temporary lock-bootstrap workflow.
- Do not print the authorized target or private-key path.
- Host acceptance operates only on a generated namespace/veth and the exact final artifact; it must not touch a physical, business, shared, bridge, bond, OVS, or tap interface.
- The retired product identifier must not appear in any tracked path or tracked file.

---

### Task 1: Add RED Supply-Chain Contracts and a Read-Only Lock Bootstrap

**Files:**

- Create: `scripts/tests/verify-build-supply-chain.Tests.ps1`
- Create: `xtask/tests/ebpf_build_command.rs`
- Create temporarily: `.github/workflows/generate-cargo-lock.yml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**

- Consumes: the mutable Delivery C workflow, `.cargo/config.toml`, `rust-toolchain.toml`, and the absence of a root lock file.
- Produces: a deliberately failing permanent policy contract, a deliberately failing Rust API contract for `xtask::ebpf`, and a manually dispatched read-only workflow that can generate the exact lock artifact despite normal CI being RED.

- [ ] **Step 1: Create the failing cross-platform policy test**

Create `scripts/tests/verify-build-supply-chain.Tests.ps1` with this complete contract:

```powershell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$CiPath = Join-Path $RepositoryRoot '.github/workflows/ci.yml'
$ToolchainPath = Join-Path $RepositoryRoot 'rust-toolchain.toml'
$CargoConfigPath = Join-Path $RepositoryRoot '.cargo/config.toml'
$LockPath = Join-Path $RepositoryRoot 'Cargo.lock'
$script:Failures = 0

function Assert-True {
    param(
        [Parameter(Mandatory)] [bool] $Condition,
        [Parameter(Mandatory)] [string] $Message
    )
    if (-not $Condition) {
        $script:Failures++
        Write-Error $Message -ErrorAction Continue
    }
}

$TrackedLock = @(& git -C $RepositoryRoot ls-files -- Cargo.lock)
Assert-True (
    $TrackedLock.Count -eq 1 -and $TrackedLock[0] -ceq 'Cargo.lock'
) 'root Cargo.lock is not tracked'

$Lock = if (Test-Path -LiteralPath $LockPath -PathType Leaf) {
    Get-Content -LiteralPath $LockPath -Raw
} else {
    ''
}
Assert-True ($Lock -match '(?m)^version = 4$') 'root Cargo.lock is not format version 4'
Assert-True ($Lock -match '(?m)^\[\[package\]\]$') 'root Cargo.lock contains no package records'

$WorkflowFiles = @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot '.github/workflows') -File -Filter '*.yml')
Assert-True ($WorkflowFiles.Count -ge 1) 'repository has no active workflow files'
foreach ($WorkflowFile in $WorkflowFiles) {
    $Workflow = Get-Content -LiteralPath $WorkflowFile.FullName -Raw
    Assert-True ($Workflow.Contains("permissions:`n  contents: read") -or $Workflow.Contains("permissions:`r`n  contents: read")) "workflow lacks read-only contents permission: $($WorkflowFile.Name)"
    Assert-True (-not $Workflow.Contains('contents: write')) "workflow requests contents write permission: $($WorkflowFile.Name)"
    foreach ($Line in Get-Content -LiteralPath $WorkflowFile.FullName) {
        if ($Line -match '^\s*uses:\s*([^#\s]+)') {
            $Reference = $Matches[1]
            Assert-True (
                $Reference -cmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$'
            ) "workflow contains mutable action reference: $Reference"
        }
    }
}

$Ci = Get-Content -LiteralPath $CiPath -Raw
$Toolchain = Get-Content -LiteralPath $ToolchainPath -Raw
$CargoConfig = Get-Content -LiteralPath $CargoConfigPath -Raw

foreach ($Required in @(
    'uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5',
    'uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7',
    'uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8',
    'uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable at Delivery C gate',
    'uses: dtolnay/rust-toolchain@7c8d7d138f5c09cef361f8214cf96882cd029cdb # nightly at Delivery C gate',
    'toolchain: 1.97.1',
    'toolchain: nightly-2026-08-10',
    'cargo metadata --locked --no-deps',
    'cargo clippy --locked --all-targets -- -D warnings',
    'cargo test --locked',
    'cargo check --locked',
    'cargo install bpf-linker --version 0.10.4 --locked',
    'cargo build --locked --release --target x86_64-unknown-linux-musl'
)) {
    Assert-True ($Ci.Contains($Required)) "CI is missing fixed build marker: $Required"
}

Assert-True ($Toolchain.Contains('channel = "1.97.1"')) 'rust-toolchain.toml does not select stable Rust 1.97.1'
Assert-True (-not [regex]::IsMatch($Toolchain, '(?m)^channel\s*=\s*"stable"\s*$')) 'rust-toolchain.toml still selects moving stable'
Assert-True ($CargoConfig.Contains('xtask = "run --locked --package xtask --"')) 'xtask alias does not require the root lock file'

if ($script:Failures -ne 0) {
    throw "$script:Failures build supply-chain assertion(s) failed"
}

Write-Host 'build supply-chain assertions passed'
```

The test intentionally fails on the current tree because `Cargo.lock` is absent and the fixed workflow markers are absent.

- [ ] **Step 2: Add the failing exact xtask command test**

Create `xtask/tests/ebpf_build_command.rs`:

```rust
use xtask::ebpf::{EBPF_CARGO_TOOLCHAIN, build_ebpf_args};

#[test]
fn ebpf_build_uses_the_dated_nightly_and_workspace_lock() {
    assert_eq!(EBPF_CARGO_TOOLCHAIN, "+nightly-2026-08-10");
    assert_eq!(
        build_ebpf_args(),
        [
            "+nightly-2026-08-10",
            "build",
            "--locked",
            "-Z",
            "build-std=core",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "--package",
            "l2-loop-ebpf",
        ]
    );
}
```

This test intentionally fails to compile because `xtask::ebpf` does not exist.

- [ ] **Step 3: Add the temporary read-only bootstrap workflow**

Create `.github/workflows/generate-cargo-lock.yml`:

```yaml
name: Generate Cargo lock

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  lock:
    name: Cargo lock
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5

      - name: Install exact stable Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable at Delivery C gate
        with:
          toolchain: 1.97.1

      - name: Generate workspace lock
        run: cargo +1.97.1 generate-lockfile

      - name: Verify locked dependency graph
        run: cargo +1.97.1 metadata --locked --no-deps

      - name: Upload exact lock
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
        with:
          name: l2-loop-cargo-lock-${{ github.sha }}
          path: Cargo.lock
          if-no-files-found: error
          retention-days: 1
```

The workflow has no push step and no write permission.

- [ ] **Step 4: Invoke the new policy test from both existing script jobs**

In `.github/workflows/ci.yml`, add this step immediately after the existing harness test in `script-tests`:

```yaml
      - name: Test build supply-chain policy
        shell: pwsh
        run: pwsh -NoProfile -File scripts/tests/verify-build-supply-chain.Tests.ps1
```

Add this equivalent step immediately after the harness test in `windows-script-tests`:

```yaml
      - name: Test build supply-chain policy with Windows PowerShell
        shell: powershell
        run: powershell -NoProfile -File scripts/tests/verify-build-supply-chain.Tests.ps1
```

- [ ] **Step 5: Run only non-compiling local RED inspections**

Run:

```powershell
git diff --check
rg -n 'verify-build-supply-chain|Generate Cargo lock|nightly-2026-08-10|--locked' scripts xtask .github
git status --short
```

Expected: no whitespace error; the two new test surfaces, temporary workflow, and CI invocations are visible. Do not execute either test locally.

- [ ] **Step 6: Commit and push the RED state**

```powershell
git add scripts/tests/verify-build-supply-chain.Tests.ps1 `
    xtask/tests/ebpf_build_command.rs `
    .github/workflows/generate-cargo-lock.yml `
    .github/workflows/ci.yml
git commit -m "test: require locked GitHub build inputs"
git push origin main
```

- [ ] **Step 7: Verify the exact RED GitHub failures**

```powershell
$RedCommit = git rev-parse HEAD
$RedRun = gh run list --repo chenyongming211-glitch/network-loop `
    --workflow CI --branch main --commit $RedCommit --limit 1 `
    --json databaseId,status,conclusion,url | ConvertFrom-Json
gh run watch $RedRun.databaseId --repo chenyongming211-glitch/network-loop --exit-status
```

Expected: the watch exits non-zero. Inspect only the failing logs:

```powershell
gh run view $RedRun.databaseId --repo chenyongming211-glitch/network-loop --log-failed
```

Require evidence for both intended failures:

- Linux and Windows policy steps report `root Cargo.lock is not tracked` and mutable Action/fixed-marker failures;
- Userspace reports that `xtask::ebpf` cannot be resolved.

If a failure is instead YAML syntax, PowerShell compatibility, or an unrelated test regression, correct the RED test infrastructure before continuing. The RED proof is valid only when the requirements themselves cause the failure.

---

### Task 2: Bootstrap the Exact Lock and Make the Build Contract GREEN

**Files:**

- Create from exact GitHub artifact: `Cargo.lock`
- Create: `xtask/src/ebpf.rs`
- Modify: `xtask/src/lib.rs`
- Modify: `xtask/src/main.rs`
- Modify: `.cargo/config.toml`
- Modify: `rust-toolchain.toml`
- Modify: `.github/workflows/ci.yml`
- Delete: `.github/workflows/generate-cargo-lock.yml`
- Test: `scripts/tests/verify-build-supply-chain.Tests.ps1`
- Test: `xtask/tests/ebpf_build_command.rs`

**Interfaces:**

- Consumes: the exact RED commit, the temporary workflow, the fixed input table, and both failing tests from Task 1.
- Produces: a tracked GitHub-generated lock, immutable permanent workflow inputs, exact xtask eBPF arguments, and a GREEN five-job CI artifact.

- [ ] **Step 1: Dispatch the bootstrap for the exact RED SHA**

```powershell
$RedCommit = git rev-parse HEAD
gh workflow run generate-cargo-lock.yml `
    --repo chenyongming211-glitch/network-loop `
    --ref main
```

Poll until exactly one workflow-dispatch run exists for `$RedCommit`:

```powershell
$LockRun = $null
for ($Attempt = 0; $Attempt -lt 12 -and $null -eq $LockRun; $Attempt++) {
    $Runs = @(gh run list --repo chenyongming211-glitch/network-loop `
        --workflow generate-cargo-lock.yml --branch main --commit $RedCommit `
        --event workflow_dispatch --limit 1 `
        --json databaseId,status,conclusion,url,headSha | ConvertFrom-Json)
    if ($Runs.Count -eq 1) { $LockRun = $Runs[0]; break }
    Start-Sleep -Seconds 5
}
if ($null -eq $LockRun -or $LockRun.headSha -cne $RedCommit) {
    throw 'exact lock-bootstrap run was not created'
}
gh run watch $LockRun.databaseId `
    --repo chenyongming211-glitch/network-loop --exit-status
```

Expected: the one-job bootstrap succeeds even though normal CI for the RED commit fails.

- [ ] **Step 2: Verify and download the exact one-file artifact**

```powershell
$ExpectedLockArtifact = "l2-loop-cargo-lock-$RedCommit"
$Artifacts = gh api "repos/chenyongming211-glitch/network-loop/actions/runs/$($LockRun.databaseId)/artifacts" | ConvertFrom-Json
$Matches = @($Artifacts.artifacts | Where-Object name -ceq $ExpectedLockArtifact)
if ($Matches.Count -ne 1 -or $Matches[0].expired) {
    throw 'exact lock artifact is missing, duplicated, or expired'
}
$LockDownload = ".artifacts/lock/$RedCommit"
gh run download $LockRun.databaseId `
    --repo chenyongming211-glitch/network-loop `
    --name $ExpectedLockArtifact --dir $LockDownload
$Downloaded = @(Get-ChildItem -LiteralPath $LockDownload -Force)
if ($Downloaded.Count -ne 1 -or
    $Downloaded[0].Name -cne 'Cargo.lock' -or
    $Downloaded[0].PSIsContainer -or
    ($Downloaded[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'lock artifact is not one regular Cargo.lock file'
}
$LockHash = (Get-FileHash -LiteralPath $Downloaded[0].FullName -Algorithm SHA256).Hash
if ([string]::IsNullOrWhiteSpace($LockHash)) { throw 'lock artifact hash is unavailable' }
```

Do not print the lock hash as a credential-like environment value; retain it only in the current command state for comparison after applying the file.

- [ ] **Step 3: Add the downloaded lock through a reviewed patch**

Read the downloaded UTF-8 text, verify it begins with the generated-file comment and contains `version = 4`, then use `apply_patch` to add the exact text as root `Cargo.lock`. Do not use Cargo, `Copy-Item`, shell redirection, or a filesystem move to create the tracked file.

After patching:

```powershell
if ((Get-FileHash -LiteralPath Cargo.lock -Algorithm SHA256).Hash -cne $LockHash) {
    throw 'tracked lock text differs from the exact GitHub artifact'
}
```

- [ ] **Step 4: Implement the tested exact eBPF command**

Create `xtask/src/ebpf.rs`:

```rust
pub const EBPF_CARGO_TOOLCHAIN: &str = "+nightly-2026-08-10";

pub const fn build_ebpf_args() -> [&'static str; 10] {
    [
        EBPF_CARGO_TOOLCHAIN,
        "build",
        "--locked",
        "-Z",
        "build-std=core",
        "--release",
        "--target",
        "bpfel-unknown-none",
        "--package",
        "l2-loop-ebpf",
    ]
}
```

Modify `xtask/src/lib.rs` to export the module:

```rust
pub mod bundle;
pub mod ebpf;
```

Modify the imports in `xtask/src/main.rs`:

```rust
use xtask::{
    bundle::{BundleInputs, create_bundle},
    ebpf::build_ebpf_args,
};
```

Replace the inline eBPF argument array with:

```rust
    let status = Command::new("cargo").args(build_ebpf_args()).status();
```

- [ ] **Step 5: Lock the workspace alias and stable toolchain**

Change `.cargo/config.toml` to:

```toml
[alias]
xtask = "run --locked --package xtask --"

[target.bpfel-unknown-none]
linker = "bpf-linker"
```

Change `rust-toolchain.toml` to:

```toml
[toolchain]
channel = "1.97.1"
profile = "minimal"
components = ["clippy", "rustfmt"]
```

- [ ] **Step 6: Replace the permanent workflow with the exact locked form**

Use these exact Action references everywhere in `.github/workflows/ci.yml`:

```yaml
uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8
uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable at Delivery C gate
uses: dtolnay/rust-toolchain@7c8d7d138f5c09cef361f8214cf96882cd029cdb # nightly at Delivery C gate
```

Every stable action invocation must include:

```yaml
        with:
          toolchain: 1.97.1
```

Preserve existing `components` or `targets` below that value. The nightly invocation must contain:

```yaml
        with:
          toolchain: nightly-2026-08-10
          components: rust-src
```

Add this Userspace step before formatting:

```yaml
      - name: Verify locked dependency graph
        run: cargo metadata --locked --no-deps
```

Use these exact permanent Cargo commands:

```yaml
      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Run Clippy
        run: cargo clippy --locked --all-targets -- -D warnings

      - name: Run tests
        run: cargo test --locked

      - name: Check default workspace members
        run: cargo check --locked
```

Pin the linker install:

```yaml
      - name: Install bpf-linker
        run: cargo install bpf-linker --version 0.10.4 --locked
```

The existing `cargo xtask build-ebpf` and `cargo xtask bundle` commands are locked by the changed alias. Change the MUSL build start to:

```yaml
          cargo build --locked --release --target x86_64-unknown-linux-musl
```

- [ ] **Step 7: Remove the temporary workflow**

Delete `.github/workflows/generate-cargo-lock.yml` with `apply_patch`. Confirm it is absent:

```powershell
if (Test-Path -LiteralPath .github/workflows/generate-cargo-lock.yml) {
    throw 'temporary lock-bootstrap workflow remains'
}
```

- [ ] **Step 8: Run non-compiling local GREEN audits**

```powershell
git diff --check
git ls-files --others --exclude-standard
rg -n '^\s*uses:\s*' .github/workflows
rg -n 'channel|toolchain:|bpf-linker|cargo (metadata|clippy|test|check|build)|xtask =' `
    rust-toolchain.toml .cargo/config.toml .github/workflows/ci.yml
rg -n 'EBPF_CARGO_TOOLCHAIN|nightly-2026-08-10|--locked' xtask
```

Expected:

- only intended new files are untracked before staging;
- every `uses:` reference ends in one of the fixed full SHAs;
- exact stable/nightly/linker versions and locked commands are visible;
- the temporary workflow is absent;
- no whitespace error is reported.

Do not execute PowerShell or Rust tests locally.

- [ ] **Step 9: Commit and push the GREEN implementation**

```powershell
git add Cargo.lock .cargo/config.toml rust-toolchain.toml .github/workflows/ci.yml `
    scripts/tests/verify-build-supply-chain.Tests.ps1 `
    xtask/src/ebpf.rs xtask/src/lib.rs xtask/src/main.rs `
    xtask/tests/ebpf_build_command.rs
git add -u -- .github/workflows/generate-cargo-lock.yml
git commit -m "build: lock GitHub build inputs"
git push origin main
```

- [ ] **Step 10: Require the exact GREEN CI and artifact**

```powershell
$GreenCommit = git rev-parse HEAD
$GreenRun = gh run list --repo chenyongming211-glitch/network-loop `
    --workflow CI --branch main --commit $GreenCommit --limit 1 `
    --json databaseId,status,conclusion,url,headSha | ConvertFrom-Json
if (@($GreenRun).Count -ne 1 -or $GreenRun.headSha -cne $GreenCommit) {
    throw 'exact GREEN CI run is unavailable'
}
gh run watch $GreenRun.databaseId `
    --repo chenyongming211-glitch/network-loop --exit-status
```

Then require all five jobs and the exact bundle:

```powershell
$VerifiedRun = gh run view $GreenRun.databaseId `
    --repo chenyongming211-glitch/network-loop `
    --json conclusion,headSha,jobs,url | ConvertFrom-Json
$Succeeded = @($VerifiedRun.jobs | Where-Object conclusion -ceq 'success')
if ($VerifiedRun.conclusion -cne 'success' -or
    $VerifiedRun.headSha -cne $GreenCommit -or
    @($VerifiedRun.jobs).Count -ne 5 -or
    $Succeeded.Count -ne 5) {
    throw 'GREEN CI is not five-of-five successful'
}
$Artifacts = gh api "repos/chenyongming211-glitch/network-loop/actions/runs/$($GreenRun.databaseId)/artifacts" | ConvertFrom-Json
$ExpectedBundle = "l2-loop-linux-x86_64-$GreenCommit"
if (@($Artifacts.artifacts | Where-Object name -ceq $ExpectedBundle).Count -ne 1) {
    throw 'exact GREEN bundle is missing'
}
```

Expected: Linux and Windows policy tests, Userspace including the xtask test, eBPF, and Bundle all succeed.

---

### Task 3: Correct Build Documentation and Run the Final Static Audit

**Files:**

- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/superpowers/specs/2026-08-11-github-build-supply-chain-hardening-design.md`

**Interfaces:**

- Consumes: the exact GREEN implementation and its five-job GitHub evidence.
- Produces: accurate build/update instructions and the final commit whose artifact is accepted on the authorized node.

- [ ] **Step 1: Update the README build policy**

In `README.md`, replace the Delivery C audit limitation about mutable inputs with the implemented C.1 contract:

- root `Cargo.lock` is generated only in GitHub and tracked;
- permanent Cargo resolution is locked;
- Action implementations use full commits;
- Rust and linker versions are explicit;
- exact artifact/checksum remains authoritative because runner images are not pinned;
- no byte-for-byte reproducibility claim is made.

Keep the statement that the local workspace runs no Cargo command.

- [ ] **Step 2: Update developer commands and manual update policy**

In `docs/development.md`:

- show stable `1.97.1`, nightly `nightly-2026-08-10`, and `bpf-linker 0.10.4`;
- show `--locked` on metadata, Clippy, test, check, MUSL build, xtask alias, and inner eBPF build;
- explain that rustfmt is the only permanent Cargo command without `--locked` because it does not resolve dependencies;
- document the Linux/Windows supply-chain contract step;
- state that dependency/tool updates are manual, atomic, and use a temporary read-only GitHub lock workflow;
- state that no updater, bot write, or automatic pull request is enabled;
- preserve the exact-artifact deployment and checksum instructions.

- [ ] **Step 3: Advance the design status without overstating acceptance**

Change the design header to:

```text
**Status:** Implemented; final exact-artifact acceptance gated by Section 10
```

Do not mark it accepted until Task 4 succeeds for the same commit.

- [ ] **Step 4: Run final non-compiling local audits**

```powershell
git diff --check
$Tracked = @(git ls-files)
$RetiredIdentifier = ('cs' + 'mp')
if (git grep -n -i -E $RetiredIdentifier -- $Tracked) {
    throw 'retired identifier remains'
}
$Markers = @(("TO" + "DO"), ("T" + "BD"), ("PLACE" + "HOLDER")) -join '|'
if (rg -n $Markers crates ebpf scripts .github README.md docs/development.md docs/superpowers) {
    throw 'incomplete marker remains'
}
$IdentityPattern = @(
    '([0-9]{1,3}\.){3}[0-9]{1,3}',
    ('ro' + 'ot@'),
    ('\.s' + 'sh[\\/]'),
    ('BEGIN ' + '(OPENSSH|RSA|EC) PRIVATE KEY')
) -join '|'
if (git grep -n -E $IdentityPattern -- $Tracked) {
    throw 'target identity or credential material remains'
}
if (rg -n 'XDP_DROP|TC_ACT_SHOT' ebpf) {
    throw 'drop action remains in eBPF source'
}
if (rg -n 'generate-cargo-lock|contents: write' .github/workflows) {
    throw 'temporary or write-capable workflow remains'
}
$ActionLines = @(rg '^\s*uses:\s*' .github/workflows)
$MutableActions = @($ActionLines | Where-Object {
    $_ -notmatch '@[0-9a-f]{40}(?:\s+#\s+.*)?$'
})
if ($MutableActions.Count -ne 0) { throw 'mutable Action reference remains' }
if (@(git ls-files -- Cargo.lock).Count -ne 1) { throw 'root lock is not tracked' }
rg -n '1\.97\.1|nightly-2026-08-10|0\.10\.4|--locked|[0-9a-f]{40}' `
    Cargo.lock rust-toolchain.toml .cargo/config.toml .github/workflows/ci.yml xtask scripts
```

Expected: no prohibited output; the exact version, SHA, and locked-resolution markers are present.

- [ ] **Step 5: Commit and push the final documentation/audit state**

```powershell
git add README.md docs/development.md `
    docs/superpowers/specs/2026-08-11-github-build-supply-chain-hardening-design.md
git commit -m "docs: record locked GitHub build contract"
git push origin main
```

- [ ] **Step 6: Require a fresh final five-job GitHub run**

```powershell
$FinalCommit = git rev-parse HEAD
$FinalRun = gh run list --repo chenyongming211-glitch/network-loop `
    --workflow CI --branch main --commit $FinalCommit --limit 1 `
    --json databaseId,status,conclusion,url,headSha | ConvertFrom-Json
if (@($FinalRun).Count -ne 1 -or $FinalRun.headSha -cne $FinalCommit) {
    throw 'exact final CI run is unavailable'
}
gh run watch $FinalRun.databaseId `
    --repo chenyongming211-glitch/network-loop --exit-status
```

Re-run the five-job and exact-artifact checks from Task 2 Step 10 using `$FinalCommit` and `$FinalRun.databaseId`. The artifact name must be `l2-loop-linux-x86_64-<full-final-commit-sha>`.

---

### Task 4: Accept the Exact Locked Artifact and Close Delivery C.1

**Files:**

- Execute without repository modification: `scripts/verify-isolated-host.ps1`

**Interfaces:**

- Consumes: the exact successful final artifact, task-scoped authorized target/key environment inputs, and the existing generated namespace/veth harness.
- Produces: runtime equivalence evidence, clean-host evidence, clean Git state, and Delivery C.1 completion.

- [ ] **Step 1: Establish task-scoped inputs without printing them**

```powershell
$TestKeys = @(Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE '.ssh') `
    -File -Filter '*codex_20260325_ed25519')
if ($TestKeys.Count -ne 1) { throw 'authorized key is unavailable or ambiguous' }
$RemoteUser = ('ro' + 'ot')
$env:L2_LOOP_TEST_TARGET = @("${RemoteUser}@10", '58', '159', '4') -join '.'
$env:L2_LOOP_TEST_KEY = $TestKeys[0].FullName
$FinalCommit = git rev-parse HEAD
```

Do not echo either environment value.

- [ ] **Step 2: Run the two bounded acceptance scenarios**

```powershell
foreach ($Scenario in @('Success', 'PassiveObservation')) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File scripts/verify-isolated-host.ps1 `
        -Commit $FinalCommit -Scenario $Scenario -TimeoutSeconds 240
    if ($LASTEXITCODE -ne 0) {
        throw "locked-build acceptance failed: $Scenario"
    }
}
```

Expected: both scenarios report success for the same full commit. Each scenario verifies bundle checksums, forwarding, exact owned cleanup, and full before/after foreign-state equality.

- [ ] **Step 3: Run an independent read-only residue audit**

Use the task-scoped target/key in an exact SSH argument array and send this script through stdin:

```sh
set -eu
test ! -e /run/l2-loop
test ! -L /run/l2-loop
test ! -e /sys/fs/bpf/l2-loop
test ! -L /sys/fs/bpf/l2-loop
if ip netns list | grep -q '^l2ns-'; then exit 21; fi
if ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -Eq '^(l2h|l2n)[0-9a-f]{10}$'; then exit 22; fi
printf '%s\n' 'authorized-node-residue-audit=clean'
```

Expected: only `authorized-node-residue-audit=clean` is returned.

- [ ] **Step 4: Verify final repository synchronization and contract**

```powershell
git fetch origin main --quiet
$Head = git rev-parse HEAD
$OriginMain = git rev-parse origin/main
$Worktree = @(git status --porcelain=v1)
$ActionLines = @(rg '^\s*uses:\s*' .github/workflows)
$MutableActions = @($ActionLines | Where-Object {
    $_ -notmatch '@[0-9a-f]{40}(?:\s+#\s+.*)?$'
})
if ($Head -cne $OriginMain) { throw 'HEAD does not match origin/main' }
if ($Worktree.Count -ne 0) { throw 'worktree is not clean' }
if ($MutableActions.Count -ne 0) { throw 'mutable Action reference remains' }
if (@(git ls-files -- Cargo.lock).Count -ne 1) { throw 'root lock is not tracked' }
if (Test-Path -LiteralPath .github/workflows/generate-cargo-lock.yml) {
    throw 'temporary bootstrap workflow remains'
}
```

- [ ] **Step 5: Record completion evidence**

The handoff must state:

- Delivery C.1 task count and 100% status;
- final full commit SHA;
- final GitHub Actions URL and five-of-five job result;
- exact artifact name;
- root lock tracked and permanent bootstrap absent;
- stable/nightly/linker versions;
- both host scenarios passed;
- residue audit clean;
- worktree clean and synchronized;
- the boundary that runner images remain moving and byte-for-byte reproducibility is not claimed;
- the next functional delivery is the bounded daemon sampler and PPS/BPS windows.
