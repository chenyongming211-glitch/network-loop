$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$CiPath = Join-Path $RepositoryRoot '.github/workflows/ci.yml'
$ToolchainPath = Join-Path $RepositoryRoot 'rust-toolchain.toml'
$CargoConfigPath = Join-Path $RepositoryRoot '.cargo/config.toml'
$AuditPolicyPath = Join-Path $RepositoryRoot '.cargo/audit.toml'
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
Assert-True ($Lock -match '(?m)^version = 4\r?$') 'root Cargo.lock is not format version 4'
Assert-True ($Lock -match '(?m)^\[\[package\]\]\r?$') 'root Cargo.lock contains no package records'

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
$AuditPolicy = if (Test-Path -LiteralPath $AuditPolicyPath -PathType Leaf) {
    Get-Content -LiteralPath $AuditPolicyPath -Raw
} else {
    ''
}

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
    'cargo install cargo-audit --version 0.22.2 --locked',
    'cargo audit',
    "git -C `"`$CARGO_HOME/advisory-db`" show -s --format='RustSec advisory database revision: %H' HEAD",
    'cargo build --locked --release --target x86_64-unknown-linux-musl',
    'L2_LOOP_BUILD_COMMIT_SHA: ${{ github.sha }}',
    '--deploy-checker target/x86_64-unknown-linux-musl/release/l2-loop-deploycheck',
    '--service-unit packaging/l2-loop.service',
    '--authorization-example packaging/deployment-v1.example.json',
    '--commit-sha "${{ github.sha }}"',
    'sha256sum --check SHA256SUMS',
    'retention-days: 14'
)) {
    Assert-True ($Ci.Contains($Required)) "CI is missing fixed build marker: $Required"
}

foreach ($Prohibited in @(
    'git rev-parse',
    'git describe',
    'curl ',
    'wget ',
    'apt-get',
    'dnf ',
    'yum ',
    'apk add',
    'echo ${{ secrets',
    'printenv',
    'set -x'
)) {
    Assert-True (-not $Ci.Contains($Prohibited)) "CI contains prohibited supply-chain marker: $Prohibited"
}

foreach ($Prohibited in @(
    'continue-on-error',
    'cargo audit fix',
    'cargo audit --ignore'
)) {
    Assert-True (-not $Ci.Contains($Prohibited)) "CI contains prohibited advisory marker: $Prohibited"
}

$AuditInstallLines = @(
    $Ci -split "`r?`n" | Where-Object { $_.Contains('cargo install cargo-audit') }
)
Assert-True (
    $AuditInstallLines.Count -eq 1 -and
    $AuditInstallLines[0].Trim() -ceq 'run: cargo install cargo-audit --version 0.22.2 --locked'
) 'cargo-audit installation is not a single exact pinned locked command'

$AuditInstall = $Ci.IndexOf('cargo install cargo-audit --version 0.22.2 --locked')
$AuditRun = $Ci.IndexOf('cargo audit', $AuditInstall + 1)
$AuditRevision = $Ci.IndexOf("RustSec advisory database revision: %H", $AuditRun + 1)
Assert-True ($AuditInstall -ge 0 -and $AuditRun -gt $AuditInstall -and $AuditRevision -gt $AuditRun) 'advisory install, audit, and revision recording are missing or out of order'

foreach ($RequiredPolicy in @(
    '[advisories]',
    'ignore = []',
    'informational_warnings = []',
    'severity_threshold = "none"',
    '[database]',
    'fetch = true',
    'stale = false',
    '[yanked]',
    'enabled = true',
    'update_index = true'
)) {
    Assert-True ($AuditPolicy.Contains($RequiredPolicy)) "cargo-audit policy is missing: $RequiredPolicy"
}
Assert-True (-not [regex]::IsMatch($AuditPolicy, '(?m)^\s*ignore\s*=\s*\[\s*[^\]\s]')) 'cargo-audit policy ignores an advisory'
Assert-True (-not [regex]::IsMatch($AuditPolicy, '(?m)^\s*informational_warnings\s*=\s*\[\s*[^\]\s]')) 'cargo-audit policy enables informational warnings as a product gate'
$ExpectedAuditPolicy = (@(
    '[advisories]',
    'ignore = []',
    'informational_warnings = []',
    'severity_threshold = "none"',
    '',
    '[database]',
    'fetch = true',
    'stale = false',
    '',
    '[yanked]',
    'enabled = true',
    'update_index = true',
    ''
) -join "`n")
Assert-True (($AuditPolicy -replace "`r`n", "`n") -ceq $ExpectedAuditPolicy) 'cargo-audit policy differs from the exact reviewed contract'

Assert-True ($Toolchain.Contains('channel = "1.97.1"')) 'rust-toolchain.toml does not select stable Rust 1.97.1'
Assert-True (-not [regex]::IsMatch($Toolchain, '(?m)^channel\s*=\s*"stable"\s*$')) 'rust-toolchain.toml still selects moving stable'
Assert-True ($CargoConfig.Contains('xtask = "run --locked --package xtask --"')) 'xtask alias does not require the root lock file'

if ($script:Failures -ne 0) {
    throw "$script:Failures build supply-chain assertion(s) failed"
}

Write-Host 'build supply-chain assertions passed'
