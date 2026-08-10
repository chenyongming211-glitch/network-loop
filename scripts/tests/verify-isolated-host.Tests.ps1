$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$ModulePath = Join-Path $RepositoryRoot 'scripts/lib/IsolatedNames.psm1'
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-isolated-host.ps1'
$WorkflowPath = Join-Path $RepositoryRoot '.github/workflows/ci.yml'

Import-Module $ModulePath -Force

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

function Assert-Throws {
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string] $Message
    )
    try {
        & $Action
        Assert-True $false $Message
    }
    catch {
        Assert-True $true $Message
    }
}

$RunId = '0123456789abcdef0123456789abcdef'
$NativeArguments = @(
    @{ Input = 'alpha'; Expected = 'alpha' },
    @{ Input = ''; Expected = '""' },
    @{ Input = 'two words'; Expected = '"two words"' },
    @{ Input = 'quote"value'; Expected = '"quote\"value"' },
    @{ Input = 'C:\path with space\'; Expected = '"C:\path with space\\"' }
)
foreach ($Case in $NativeArguments) {
    $Actual = ConvertTo-WindowsNativeArgument -Argument $Case.Input
    Assert-True ($Actual -ceq $Case.Expected) "Windows native argv escaping changed for: $($Case.Input)"
}

$Names = New-IsolatedNames -RunId $RunId
$NamesAgain = New-IsolatedNames -RunId $RunId
Assert-True ($Names.Namespace -ceq $NamesAgain.Namespace) 'namespace name is not deterministic'
Assert-True ($Names.HostVeth -ceq $NamesAgain.HostVeth) 'host veth name is not deterministic'
Assert-True ($Names.PeerVeth -ceq $NamesAgain.PeerVeth) 'peer veth name is not deterministic'
Assert-True ($Names.Namespace -ceq 'l2ns-0123456789ab') 'unexpected namespace name'
Assert-True ($Names.HostVeth -ceq 'l2h0123456789') 'unexpected host veth name'
Assert-True ($Names.PeerVeth -ceq 'l2n0123456789') 'unexpected peer veth name'
Assert-True ($Names.HostVeth.Length -le 15) 'host veth exceeds Linux interface name limit'
Assert-True ($Names.PeerVeth.Length -le 15) 'peer veth exceeds Linux interface name limit'

foreach ($InvalidRunId in @('', 'abc', ('A' * 32), ('g' * 32), ('0' * 31), ('0' * 33), '../unsafe')) {
    Assert-Throws { New-IsolatedNames -RunId $InvalidRunId } "accepted invalid run ID: $InvalidRunId"
}

$Ssh = Get-SshArguments -Target 'operator@test.invalid' -KeyPath '/private/key' -RemoteArguments @('ip', '-j', 'link', 'show')
$ExpectedSsh = @(
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-i', '/private/key',
    '--', 'operator@test.invalid',
    'ip', '-j', 'link', 'show'
)
Assert-True (($Ssh -join "`n") -ceq ($ExpectedSsh -join "`n")) 'SSH argv is not exact'

Assert-CleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot
Assert-Throws {
    Assert-CleanupTarget -Names $Names -Namespace 'foreign' -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot
} 'accepted foreign namespace cleanup target'
Assert-Throws {
    Assert-CleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth 'eth0' -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot
} 'accepted non-generated interface cleanup target'
Assert-Throws {
    Assert-CleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot '/run/l2-loop'
} 'accepted broad cleanup root'

$Harness = Get-Content $HarnessPath -Raw
$Workflow = Get-Content $WorkflowPath -Raw

foreach ($Required in @(
    'L2_LOOP_TEST_TARGET',
    'L2_LOOP_TEST_KEY',
    'Register-IsolatedCleanup',
    'Invoke-IsolatedMutation',
    'finally',
    'PowerShell.Exiting',
    'CancelKeyPress',
    'TimeoutSeconds',
    'Test-IsolatedRemoteState',
    'Assert-IsolatedRemoteStateUnchanged',
    'Wait-IsolatedRemoteState',
    "[ValidateSet('snapshot', 'snapshot-prepared')] [string] `$Phase = 'snapshot'",
    "snapshot_prepared()",
    "snapshot-prepared)",
    'sum(1 for item in value if item.get("ifname") == excluded) != 1',
    'item for item in value if item.get("ifname") != excluded',
    '[ValidateRange(1, 5)] [int] $MaxAttempts = 5',
    '[ValidateRange(10, 100)] [int] $DelayMilliseconds = 100',
    "Start-Sleep -Milliseconds `$DelayMilliseconds",
    'Assert-NoSymlink',
    'Assert-GeneratedTarget',
    'SHA256SUMS',
    'HOOK_STATS',
    'l2-loop-hostcheck',
    "'snapshot'",
    "'verify-owned'",
    "'counters'",
    "[ValidateSet('Success', 'TcAttachFailure', 'MapInitializeFailure', 'DaemonTermination', 'IdentityChange', 'TrafficInterruption')]",
    'L2_LOOP_ACCEPTANCE_FAULT',
    'TC_ATTACH_FAILED',
    'MAP_INITIALIZE_FAILED',
    "'stop-daemon'",
    "'alter-journal'",
    "'restore-journal'",
    "'traffic-interrupt'"
)) {
    Assert-True ($Harness.Contains($Required)) "harness is missing required safety marker: $Required"
}

Assert-True (-not $Harness.Contains('bpftool')) 'harness requires bpftool on the target host'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)command_name in[^\r\n]*\btc\b')) 'harness requires tc on the target host'

Assert-True ($Harness.IndexOf('$ExitEvent = Register-IsolatedCleanup') -lt $Harness.IndexOf('$null = Invoke-IsolatedMutation')) 'cleanup is not registered before first mutation'
Assert-True ($Harness.Contains("Where-Object { `$null -ne `$_ -and")) 'empty GitHub run queries are not rejected safely'
Assert-True ([regex]::Matches($Harness, [regex]::Escape('Wait-IsolatedRemoteState')).Count -ge 5) 'bounded exact-state convergence is not used at every rollback boundary'
$PreparedMarker = '$PreparedState = Test-IsolatedRemoteState'
$LinksUpMarker = '$null = Invoke-IsolatedMutation -Phase ''links-up'''
Assert-True ($Harness.IndexOf($PreparedMarker) -ge 0 -and $Harness.IndexOf($PreparedMarker) -lt $Harness.IndexOf($LinksUpMarker)) 'generated veth is raised before the transaction completes isolated attach'
Assert-True ($Harness.Contains("`$PreparedState = Test-IsolatedRemoteState -Phase 'snapshot-prepared'")) 'prepared state includes the generated veth volatile link record'
Assert-True ([regex]::Matches($Harness, [regex]::Escape("Wait-IsolatedRemoteState -Phase 'snapshot-prepared'")).Count -ge 2) 'transaction rollback boundaries do not use the prepared-state snapshot'
Assert-True ([regex]::Matches($Harness, [regex]::Escape("Test-IsolatedRemoteState -Phase 'snapshot-prepared'")).Count -eq 1) 'prepared-state filtering is not limited to the generated transaction snapshot'
Assert-True ([regex]::Matches($Harness, [regex]::Escape('$BeforeState = Test-IsolatedRemoteState -Names')).Count -eq 1) 'full host snapshot is not captured before isolated mutation'
Assert-True ([regex]::Matches($Harness, [regex]::Escape('Wait-IsolatedRemoteState -Expected $BeforeState')).Count -ge 2) 'full host state is not verified after cleanup paths'
Assert-True (-not $Harness.Contains("'verify-hooks-saved'")) 'hostcheck is asked to trust a non-canonical ownership journal path'
$IdentityCanonicalVerification = "(?s)'IdentityChange' \{(?:(?!'TrafficInterruption').)*restore-journal(?:(?!'TrafficInterruption').)*-Phase 'verify-hooks'"
Assert-True ([regex]::IsMatch($Harness, $IdentityCanonicalVerification)) 'identity-change rejection is not verified after restoring the canonical journal'
Assert-True (-not $Harness.Contains("prepare-pins")) 'harness creates the transaction-owned pin parents'
Assert-True ($Harness.IndexOf('ulimit -l unlimited') -ge 0 -and $Harness.IndexOf('ulimit -l unlimited') -lt $Harness.IndexOf('./l2-loopd')) 'daemon is launched before the isolated child memlock limit is raised'
Assert-True ($Workflow.Contains('script-tests:')) 'CI script-tests job is missing'
Assert-True ($Workflow.Contains('pwsh -NoProfile -File scripts/tests/verify-isolated-host.Tests.ps1')) 'CI does not run the self-contained harness tests'

foreach ($Forbidden in @(
    'rm -rf',
    'rm -r ',
    'cleanup-all',
    'eval ',
    'Invoke-Expression',
    'apt-get',
    'apt ',
    'dnf ',
    'yum ',
    'zypper ',
    'systemctl',
    'service ',
    'sysctl',
    'ethtool',
    'ovs-',
    'ip link set master',
    'bond'
)) {
    Assert-True (-not $Harness.Contains($Forbidden)) "harness contains forbidden text: $Forbidden"
}

Assert-True (-not [regex]::IsMatch($Harness, '(?m)(Remove-Item|rm|unlink)[^\r\n]*[\*\?]')) 'cleanup uses a wildcard target'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)ssh[^\r\n]*\$\(')) 'SSH command uses command substitution/interpolation'
Assert-True (-not [regex]::IsMatch($Harness, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')) 'harness contains a hard-coded IPv4 target'

if ($script:Failures -ne 0) {
    throw "$script:Failures isolated host harness safety assertion(s) failed"
}

Write-Host 'isolated host harness safety assertions passed'
