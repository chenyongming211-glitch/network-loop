$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-installation.ps1'
$WorkflowPath = Join-Path $RepositoryRoot '.github/workflows/ci.yml'
$InstallerCliPath = Join-Path $RepositoryRoot 'crates/l2-loop-agent/src/installation_cli.rs'
$InstallerBinPath = Join-Path $RepositoryRoot 'crates/l2-loop-agent/src/bin/install.rs'
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

$Harness = if (Test-Path -LiteralPath $HarnessPath -PathType Leaf) {
    Get-Content -LiteralPath $HarnessPath -Raw
} else {
    ''
}
$Workflow = Get-Content -LiteralPath $WorkflowPath -Raw
$InstallerSurface = (Get-Content -LiteralPath $InstallerCliPath -Raw) +
    (Get-Content -LiteralPath $InstallerBinPath -Raw)

$HappyScenarios = @(
    'FreshInstall',
    'IdempotentPlan',
    'ExactOwnedUpgrade',
    'InterruptedApplyRecovery',
    'RestartRecovery',
    'ExactRollback',
    'ForeignObjectRefusal',
    'UnsafeMetadataRefusal',
    'IdentityDisagreementRefusal',
    'ZeroResidue'
)
$FaultSelectors = @(
    'DirectoryCreate',
    'SiblingCreate',
    'PayloadWrite',
    'Ownership',
    'Mode',
    'Hash',
    'FileSync',
    'BackupRename',
    'FinalRename',
    'DirectorySync',
    'JournalSync',
    'JournalMove',
    'Verify',
    'Rollback'
)

Assert-True ($HappyScenarios.Count -eq 10) 'generated-root happy scenario count changed'
Assert-True ($FaultSelectors.Count -eq 14) 'generated-root fault selector count changed'
Assert-True (-not [string]::IsNullOrEmpty($Harness)) 'generated-root installation harness is missing'

foreach ($Required in @(
    "[ValidatePattern('^[0-9a-f]{40}$')]",
    '$GENERATED_PARENT_NAME = ''l2-loop-install-acceptance-v1''',
    '$EXPECTED_BUNDLE_FILE_COUNT = 10',
    '$EXPECTED_CHECKSUM_COUNT = 9',
    '$EXPECTED_HAPPY_SCENARIO_COUNT = 10',
    '$EXPECTED_FAULT_SELECTOR_COUNT = 14',
    "'^[0-9a-f]{32}$'",
    '[Security.Cryptography.RandomNumberGenerator]::Create()',
    'Assert-ExactArtifact',
    'Assert-ArtifactChecksums',
    'Assert-ArtifactManifest',
    'Assert-GeneratedPathContained',
    'Assert-NoFollowPath',
    'Register-GeneratedCleanup',
    'Unregister-GeneratedCleanup',
    'PowerShell.Exiting',
    'CancelKeyPress',
    'New-StrictDeploymentAuthorization',
    'New-StrictPerformanceEvidence',
    'New-StrictInstallAuthorization',
    'issued_at_unix_ms',
    'expires_at_unix_ms',
    'service_enable = $false',
    'service_start = $false',
    'physical_attach = $false',
    'Invoke-GeneratedInstallationEntryPoint',
    'L2_LOOP_INSTALL_ACCEPTANCE_ROOT',
    'L2_LOOP_INSTALL_ACCEPTANCE_HOST_IDENTITY',
    'L2_LOOP_INSTALL_ACCEPTANCE_FAULT',
    'installation_fs',
    'installation_faults',
    'outside_root_before',
    'outside_root_after',
    'outside_root_unchanged',
    'generated_root_removed',
    'residue_count',
    'generated_installation_verified',
    'schema_version = 1',
    'mutations_performed',
    'SHA256SUMS',
    'manifest.json',
    'l2-loop-install'
)) {
    Assert-True ($Harness.Contains($Required)) "installation harness is missing required marker: $Required"
}

foreach ($Scenario in $HappyScenarios) {
    Assert-True ($Harness.Contains("'$Scenario'")) "installation harness is missing scenario: $Scenario"
}
foreach ($Fault in $FaultSelectors) {
    Assert-True ($Harness.Contains("'$Fault'")) "installation harness is missing fault selector: $Fault"
}

$ChecksumIndex = $Harness.IndexOf('Assert-ArtifactChecksums', [StringComparison]::Ordinal)
$RootCreateIndex = $Harness.IndexOf('New-GeneratedRoot', [StringComparison]::Ordinal)
Assert-True (
    $ChecksumIndex -ge 0 -and $RootCreateIndex -gt $ChecksumIndex
) 'generated root can be created before artifact checksum verification'

$CleanupRegisterIndex = $Harness.IndexOf('Register-GeneratedCleanup', [StringComparison]::Ordinal)
Assert-True (
    $CleanupRegisterIndex -ge 0 -and $RootCreateIndex -gt $CleanupRegisterIndex
) 'generated cleanup is not registered before root creation'

foreach ($ProhibitedPattern in @(
    '(?im)\bssh(?:\.exe)?\b',
    '(?im)\bsystemctl\b',
    '(?im)\bjournalctl\b',
    '(?im)(?:^|[\s''"])(?:ip|tc|bpftool)(?:[\s''"]|$)',
    '(?im)\baya\b',
    '(?im)physical[_ -]?interface',
    '(?im)default route',
    '(?im)Remove-Item[^\r\n]*-Recurse',
    '(?im)Get-ChildItem[^\r\n]*-Recurse',
    '(?im)\brm\s+-(?:r|rf|fr)\b',
    '(?im)\bdel\s+/s\b',
    '(?im)\bforce\b',
    '(?im)\brepair\b',
    '(?im)\badopt\b'
)) {
    Assert-True (-not [regex]::IsMatch($Harness, $ProhibitedPattern)) "installation harness contains prohibited pattern: $ProhibitedPattern"
}

foreach ($ProhibitedLiteral in @(
    'L2_LOOP_INSTALL_ROOT',
    'L2_LOOP_INSTALL_PREFIX',
    '--root',
    '--prefix',
    '--destination',
    'Remove-Item *',
    'Get-ChildItem *',
    'rm *'
)) {
    Assert-True (-not $Harness.Contains($ProhibitedLiteral)) "installation harness contains prohibited literal: $ProhibitedLiteral"
    Assert-True (-not $InstallerSurface.Contains($ProhibitedLiteral)) "production installer exposes prohibited literal: $ProhibitedLiteral"
}

foreach ($WorkflowMarker in @(
    'Test generated-root installation harness safety',
    'Test generated-root installation harness with Windows PowerShell',
    'scripts/tests/verify-installation.Tests.ps1',
    'Download exact release bundle for generated-root acceptance',
    'Run generated-root installation acceptance',
    'scripts/verify-installation.ps1',
    '-Commit "${{ github.sha }}"',
    'l2-loop-linux-x86_64-${{ github.sha }}'
)) {
    Assert-True ($Workflow.Contains($WorkflowMarker)) "CI is missing generated-root acceptance marker: $WorkflowMarker"
}

$HarnessTestCalls = @(
    [regex]::Matches($Workflow, [regex]::Escape('scripts/tests/verify-installation.Tests.ps1'))
).Count
Assert-True ($HarnessTestCalls -eq 2) 'generated-root safety test must run exactly once on Linux and once on Windows'

if ($script:Failures -ne 0) {
    throw "$($script:Failures) generated-root installation safety assertions failed"
}

Write-Host 'generated-root installation safety assertions passed'
