$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-installed-service.ps1'
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
    Assert-True $false 'installed service acceptance harness is missing'
}
else {
    foreach ($Required in @(
        "[ValidatePattern('^[0-9a-f]{40}$')]",
        "[ValidatePattern('^[0-9a-f]{32}$')]",
        'L2_LOOP_TEST_TARGET',
        'L2_LOOP_TEST_KEY',
        '$MAX_OUTPUT_BYTES = 1048576',
        '$SERVICE_CYCLE_COUNT = 2',
        '$STOP_TIMEOUT_SECONDS = 10',
        '$SOCKET_MODE = ''600''',
        'ServiceAuthorizationPath',
        'InstallTransactionId',
        'Assert-StrictServiceAuthorization',
        'service_acceptance',
        'artifact_commit_sha',
        'host_identity_sha256',
        'install_transaction_id',
        'issued_at_unix_ms',
        'expires_at_unix_ms',
        'service_enable',
        'physical_attach',
        'generated_only',
        '[Security.Cryptography.RandomNumberGenerator]::Create()',
        'ControllerOwnershipNonce',
        'New-ServiceAcceptanceNames',
        'assert_owned',
        'Assert-ServiceCleanupTarget',
        'Register-ServiceCleanup',
        'Unregister-ServiceCleanup',
        'PowerShell.Exiting',
        'CancelKeyPress',
        'Get-StableServiceHostState',
        'Wait-StableServiceHostState',
        'Assert-ServiceHostStateUnchanged',
        "'is-enabled'",
        "'is-active'",
        "'disabled'",
        "'static'",
        "'inactive'",
        "'daemon-reload'",
        "'start'",
        "'stop'",
        'Wait-ServiceInactive',
        'journal_cursor_before',
        'journal_cursor_after',
        "'--after-cursor'",
        "'_SYSTEMD_UNIT=l2-loop.service'",
        "'json'",
        'Assert-SanitizedJournalRecords',
        'journal record set is empty',
        'agent.sock',
        'root_socket_verified',
        "'isolated-attach'",
        "'isolated-detach'",
        "'observe'",
        "'status'",
        "'--json'",
        'L2_LOOP_ACCEPTANCE_EVIDENCE_ROOT',
        'Start-InjectedFallbackDaemon',
        'stderr_fallback_verified',
        'evidence_persistence_verified',
        'service_cycle_count',
        'network_identity_before',
        'network_identity_after',
        'ebpf_identity_before',
        'ebpf_identity_after',
        'owned_cleanup_complete',
        'service_work_parent_created',
        'service_verified',
        'schema_version = 1',
        'mutations_performed = $true'
    )) {
        Assert-True ($Harness.Contains($Required)) "installed service harness is missing required marker: $Required"
    }

    $StateIndex = $Harness.IndexOf('$PriorUnitState = Get-PriorUnitState', [StringComparison]::Ordinal)
    $BaselineIndex = $Harness.IndexOf('$BeforeState = Wait-StableServiceHostState', [StringComparison]::Ordinal)
    $ReloadIndex = $Harness.IndexOf("'daemon-reload'", [StringComparison]::Ordinal)
    $StartIndex = $Harness.IndexOf('$StartResult = Invoke-ServiceCommand', [StringComparison]::Ordinal)
    $StopIndex = $Harness.IndexOf('$StopResult = Invoke-ServiceCommand', [StringComparison]::Ordinal)
    $AfterIndex = $Harness.IndexOf('$AfterState = Wait-StableServiceHostState', [StringComparison]::Ordinal)
    Assert-True ($StateIndex -ge 0 -and $BaselineIndex -gt $StateIndex) 'service baseline precedes prior unit-state refusal'
    Assert-True ($ReloadIndex -gt $BaselineIndex) 'daemon-reload precedes stable host baseline'
    Assert-True ($StartIndex -gt $ReloadIndex) 'service starts before daemon-reload'
    Assert-True ($StopIndex -gt $StartIndex) 'service stop is not sequenced after start'
    Assert-True ($AfterIndex -gt $StopIndex) 'final host comparison precedes service stop'

    foreach ($Prohibited in @(
        '(?im)^\s*param\([\s\S]*?\[string\]\s+\$Interface\b',
        '(?im)\bdefault\s+route\b',
        '(?im)\bsystemctl\s+(?:enable|disable|reenable|restart|try-restart|reload-or-restart|set-property|edit)\b',
        '(?im)\b(?:apt|apt-get|dnf|yum|zypper)\b',
        '(?im)\b(?:sysctl|modprobe|insmod|rmmod|ethtool)\b',
        '(?im)\b(?:pkill|killall)\b',
        '(?im)\bbpftool\b[^\r\n]*(?:detach|delete|del)\b',
        '(?im)\bip\b[^\r\n]*(?:addr|address|route)\s+(?:add|append|change|delete|del|flush|replace)\b',
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
        Assert-True (-not [regex]::IsMatch($Harness, $Prohibited)) "installed service harness contains prohibited pattern: $Prohibited"
    }
    Assert-True (-not [regex]::IsMatch($Harness, '(?im)\b(?:Remove-Item|rm|unlink)\b[^\r\n]*[\*\?]')) 'installed service cleanup uses a wildcard target'
    Assert-True (-not $Harness.Contains('physical_interface')) 'installed service report exposes a physical-interface field'
}

foreach ($WorkflowMarker in @(
    'Test real installation acceptance harness safety',
    'Test installed service acceptance harness safety',
    'Test installed service acceptance harness with Windows PowerShell',
    'Test real installation acceptance harness with Windows PowerShell',
    'scripts/tests/verify-real-install.Tests.ps1',
    'scripts/tests/verify-installed-service.Tests.ps1'
)) {
    Assert-True ($Workflow.Contains($WorkflowMarker)) "CI is missing installed service safety marker: $WorkflowMarker"
}

if ($script:Failures -ne 0) {
    throw "$script:Failures installed service acceptance safety assertion(s) failed"
}

Write-Host 'installed service acceptance safety assertions passed'
