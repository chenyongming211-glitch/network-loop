$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-real-service-acceptance.ps1'
$InnerHarnessPath = Join-Path $RepositoryRoot 'scripts/verify-installed-service.ps1'
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
$InnerHarness = if (Test-Path -LiteralPath $InnerHarnessPath -PathType Leaf) {
    Get-Content -LiteralPath $InnerHarnessPath -Raw
} else {
    ''
}
$Workflow = Get-Content -LiteralPath $WorkflowPath -Raw

if ([string]::IsNullOrEmpty($Harness)) {
    Assert-True $false 'real service acceptance harness is missing'
}
else {
    foreach ($Required in @(
        "[ValidatePattern('^[0-9a-f]{40}$')]",
        'InstallAuthorizationPath',
        'RollbackAuthorizationPath',
        'ServiceAuthorizationPath',
        'DeploymentAuthorizationPath',
        'PerformanceEvidencePath',
        'L2_LOOP_TEST_TARGET',
        'L2_LOOP_TEST_KEY',
        '$MAX_OUTPUT_BYTES = 1048576',
        '$EXPECTED_BUNDLE_FILE_COUNT = 10',
        '$EXPECTED_CHECKSUM_COUNT = 9',
        'Get-ExactGreenInstallBundle',
        'Assert-ExactBundle',
        'Assert-StrictInstallAuthorization',
        'Get-StableRealInstallState',
        'Assert-RealInstallStateUnchanged',
        'ControllerOwnershipNonce',
        'Register-RealInstallCleanup',
        'Unregister-RealInstallCleanup',
        'verify-installed-service.ps1',
        '$InstalledVerification = Invoke-RemoteInstallPhase',
        '$ServiceVerification = & $ServiceHarness',
        '$RollbackResult = Invoke-RemoteInstallPhase',
        'installed_verified',
        'service_verified',
        'rolled_back',
        'real_service_acceptance_verified',
        'network_identity_before',
        'network_identity_after',
        'ebpf_identity_before',
        'ebpf_identity_after',
        'outside_install_state_unchanged',
        'owned_cleanup_complete = [bool]$ServiceVerification.owned_cleanup_complete',
        'generated_residue_count',
        'schema_version = 1',
        'mutations_performed = $true'
    )) {
        Assert-True ($Harness.Contains($Required)) "real service acceptance harness is missing required marker: $Required"
    }

    $PlanIndex = $Harness.IndexOf('$PlanResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    $ApplyIndex = $Harness.IndexOf('$ApplyResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    $InstalledIndex = $Harness.IndexOf('$InstalledVerification = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    $ServiceIndex = $Harness.IndexOf('$ServiceVerification = & $ServiceHarness', [StringComparison]::Ordinal)
    $RollbackIndex = $Harness.IndexOf('$RollbackResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
    Assert-True ($PlanIndex -ge 0) 'Gate 2 installation plan is absent'
    Assert-True ($ApplyIndex -gt $PlanIndex) 'Gate 2 apply does not follow plan'
    Assert-True ($InstalledIndex -gt $ApplyIndex) 'Gate 2 installed verification does not follow apply'
    Assert-True ($ServiceIndex -gt $InstalledIndex) 'Gate 2 service can run before installed verification'
    Assert-True ($RollbackIndex -gt $ServiceIndex) 'Gate 2 rollback does not follow service acceptance'

    foreach ($Prohibited in @(
        '(?im)^\s*param\([\s\S]*?\[string\]\s+\$Interface\b',
        '(?im)\bdefault\s+route\b',
        '(?im)\bsystemctl\s+(?:enable|disable|reenable|restart|try-restart|reload-or-restart|set-property|edit)\b',
        '(?im)\b(?:apt|apt-get|dnf|yum|zypper)\b',
        '(?im)\b(?:sysctl|modprobe|insmod|rmmod|ethtool)\b',
        '(?im)\b(?:pkill|killall)\b',
        '(?im)\bbpftool\b[^\r\n]*(?:detach|delete|del)\b',
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
        Assert-True (-not [regex]::IsMatch($Harness, $Prohibited)) "real service acceptance harness contains prohibited pattern: $Prohibited"
    }
    Assert-True (-not [regex]::IsMatch($Harness, '(?im)\b(?:Remove-Item|rm|unlink)\b[^\r\n]*[\*\?]')) 'real service acceptance cleanup uses a wildcard target'
    Assert-True (-not $Harness.Contains('physical_canary_ready')) 'real service acceptance can claim physical readiness'
}

Assert-True (-not [string]::IsNullOrEmpty($InnerHarness)) 'narrow installed service harness is missing'
Assert-True ($InnerHarness.Contains("'isolated-attach'")) 'inner service harness lacks generated-veth attach'
Assert-True ($InnerHarness.Contains('generated_only')) 'inner service authorization is not generated-only'
Assert-True (-not $InnerHarness.Contains('physical_interface')) 'inner service report exposes a physical interface'

foreach ($WorkflowMarker in @(
    'Test real service acceptance harness safety',
    'Test real service acceptance harness with Windows PowerShell',
    'scripts/tests/verify-real-service-acceptance.Tests.ps1'
)) {
    Assert-True ($Workflow.Contains($WorkflowMarker)) "CI is missing real service acceptance marker: $WorkflowMarker"
}

if ($script:Failures -ne 0) {
    throw "$script:Failures real service acceptance safety assertion(s) failed"
}

Write-Host 'real service acceptance safety assertions passed'
