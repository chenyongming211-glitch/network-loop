$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-real-install.ps1'
$WorkflowPath = Join-Path $RepositoryRoot '.github/workflows/ci.yml'
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

if ([string]::IsNullOrEmpty($Harness)) {
    Assert-True $false 'real installation acceptance harness is missing'
}
else {
    foreach ($Required in @(
        "[ValidatePattern('^[0-9a-f]{40}$')]",
        'L2_LOOP_TEST_TARGET',
        'L2_LOOP_TEST_KEY',
        '$MAX_OUTPUT_BYTES = 1048576',
        '$EXPECTED_BUNDLE_FILE_COUNT = 10',
        '$EXPECTED_CHECKSUM_COUNT = 9',
        'InstallAuthorizationPath',
        'RollbackAuthorizationPath',
        'ServiceAuthorizationPath',
        'DeploymentAuthorizationPath',
        'PerformanceEvidencePath',
        'Get-ExactGreenInstallBundle',
        'Assert-ExactBundle',
        'ControllerOwnershipNonce',
        'assert_owned',
        'Assert-StrictInstallAuthorization',
        'Get-StableRealInstallState',
        'Assert-RealInstallStateUnchanged',
        'Register-RealInstallCleanup',
        'Unregister-RealInstallCleanup',
        'PowerShell.Exiting',
        'CancelKeyPress',
        'Invoke-RemoteInstallPhase',
        'Assert-InstallDecision',
        'l2-loop-install',
        "'plan'",
        "'apply'",
        "'rollback'",
        'l2-loop-deploycheck',
        "'installed'",
        'installed_verified',
        'service_verified',
        'rolled_back',
        'verify-installed-service.ps1',
        '$InstalledVerification = Invoke-RemoteInstallPhase',
        '$ServiceVerification = & $ServiceHarness',
        '$RollbackResult = Invoke-RemoteInstallPhase',
        'network_identity_before',
        'network_identity_after',
        'ebpf_identity_before',
        'ebpf_identity_after',
        'outside_install_state_unchanged',
        'generated_residue_count',
        'real_install_verified',
        'schema_version = 1',
        'mutations_performed = $true',
        'SHA256SUMS',
        'manifest.json'
    )) {
        Assert-True ($Harness.Contains($Required)) "real installation harness is missing required marker: $Required"
    }

    $BundleIndex = $Harness.IndexOf('Assert-ExactBundle', [StringComparison]::Ordinal)
    $PlanIndex = $Harness.IndexOf('$PlanResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    $ApplyIndex = $Harness.IndexOf('$ApplyResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    $InstalledIndex = $Harness.IndexOf('$InstalledVerification = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    $ServiceIndex = $Harness.IndexOf('$ServiceVerification = & $ServiceHarness', [StringComparison]::Ordinal)
    $RollbackIndex = $Harness.IndexOf('$RollbackResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    Assert-True ($BundleIndex -ge 0 -and $PlanIndex -gt $BundleIndex) 'installation plan precedes exact bundle validation'
    Assert-True ($ApplyIndex -gt $PlanIndex) 'installation apply does not follow the accepted plan'
    Assert-True ($InstalledIndex -gt $ApplyIndex) 'installed layout is checked before apply'
    Assert-True ($ServiceIndex -gt $InstalledIndex) 'service acceptance can run before installed_verified'
    Assert-True ($RollbackIndex -gt $ServiceIndex) 'exact rollback is not sequenced after service acceptance'

    foreach ($Prohibited in @(
        '(?im)^\s*param\([\s\S]*?\[string\]\s+\$Interface\b',
        '(?im)\bdefault\s+route\b',
        '(?im)\bsystemctl\b',
        '(?im)\bjournalctl\b',
        '(?im)\b(?:apt|apt-get|dnf|yum|zypper)\b',
        '(?im)\b(?:sysctl|modprobe|insmod|rmmod|ethtool)\b',
        '(?im)\b(?:pkill|killall)\b',
        '(?im)\bRemove-Item\b[^\r\n]*-Recurse',
        '(?im)\brm\s+-(?:r|rf|fr)\b',
        '(?im)\bInvoke-Expression\b',
        '(?im)(?:^|\s)eval\s',
        '(?im)\bforce\b',
        '(?im)\brepair\b',
        '(?im)\badopt\b',
        '(?im)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        '(?im)\.ssh[\\/]'
    )) {
        Assert-True (-not [regex]::IsMatch($Harness, $Prohibited)) "real installation harness contains prohibited pattern: $Prohibited"
    }
    Assert-True (-not [regex]::IsMatch($Harness, '(?im)\b(?:Remove-Item|rm|unlink)\b[^\r\n]*[\*\?]')) 'real installation cleanup uses a wildcard target'
}

foreach ($WorkflowMarker in @(
    'Test real installation acceptance harness safety',
    'Test installed service acceptance harness safety',
    'Test installed service acceptance harness with Windows PowerShell',
    'Test real installation acceptance harness with Windows PowerShell',
    'scripts/tests/verify-real-install.Tests.ps1',
    'scripts/tests/verify-installed-service.Tests.ps1'
)) {
    Assert-True ($Workflow.Contains($WorkflowMarker)) "CI is missing real installation safety marker: $WorkflowMarker"
}

if ($script:Failures -ne 0) {
    throw "$script:Failures real installation acceptance safety assertion(s) failed"
}

Write-Host 'real installation acceptance safety assertions passed'
