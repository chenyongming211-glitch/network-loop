$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$ModulePath = Join-Path $RepositoryRoot 'scripts/lib/IsolatedNames.psm1'
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-deployment-gates.ps1'
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
$Names = New-DeploymentGateNames -RunId $RunId
Assert-True ($Names.RunId -ceq $RunId) 'deployment run ID changed'
Assert-True ($Names.Namespace -ceq 'l2ns-0123456789ab') 'deployment namespace is not generated'
Assert-True ($Names.HostVeth -ceq 'l2h0123456789') 'deployment host veth is not generated'
Assert-True ($Names.PeerVeth -ceq 'l2n0123456789') 'deployment peer veth is not generated'
Assert-True ($Names.RemoteRunRoot -ceq "/run/l2-loop/accept/$RunId") 'deployment run root is not exact'
Assert-True ($Names.BundleRoot -ceq "/run/l2-loop/accept/$RunId/bundle") 'deployment bundle root is not exact'
Assert-True ($Names.StagingRoot -ceq "/run/l2-loop/accept/$RunId/staging-root") 'deployment staging root is not exact'
Assert-True ($Names.AuthorizationPath -ceq "/run/l2-loop/accept/$RunId/staging-root/etc/l2-loop/deployment-v1.json") 'authorization path is not generated'
Assert-True ($Names.PerformancePath -ceq "/run/l2-loop/accept/$RunId/staging-root/var/lib/l2-loop/gates/performance-v1.json") 'performance path is not generated'

foreach ($InvalidRunId in @('', 'abc', ('A' * 32), ('g' * 32), ('0' * 31), ('0' * 33), '../unsafe')) {
    Assert-Throws { New-DeploymentGateNames -RunId $InvalidRunId } "accepted invalid deployment run ID: $InvalidRunId"
}

Assert-DeploymentCleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot -BundleRoot $Names.BundleRoot -StagingRoot $Names.StagingRoot
Assert-Throws {
    Assert-DeploymentCleanupTarget -Names $Names -Namespace 'foreign' -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot -BundleRoot $Names.BundleRoot -StagingRoot $Names.StagingRoot
} 'accepted foreign namespace cleanup target'
Assert-Throws {
    Assert-DeploymentCleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth 'eth0' -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot -BundleRoot $Names.BundleRoot -StagingRoot $Names.StagingRoot
} 'accepted physical or business cleanup target'
Assert-Throws {
    Assert-DeploymentCleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot '/run/l2-loop/accept' -BundleRoot $Names.BundleRoot -StagingRoot $Names.StagingRoot
} 'accepted broad run-root cleanup target'
Assert-Throws {
    Assert-DeploymentCleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot -BundleRoot $Names.BundleRoot -StagingRoot '/'
} 'accepted broad staging-root cleanup target'

$Harness = Get-Content -LiteralPath $HarnessPath -Raw
$Workflow = Get-Content -LiteralPath $WorkflowPath -Raw

foreach ($Required in @(
    'L2_LOOP_TEST_TARGET',
    'L2_LOOP_TEST_KEY',
    '[Security.Cryptography.RandomNumberGenerator]::Create()',
    "[ValidatePattern('^[0-9a-f]{40}$')]",
    '[ValidateRange(60, 1800)]',
    '$MAX_OUTPUT_BYTES = 1048576',
    '$PERFORMANCE_FRAME_SIZES = @(64, 512, 1514)',
    '$PERFORMANCE_FRAMES_PER_SIZE = 65536',
    '$PERFORMANCE_TRIAL_COUNT = 5',
    '$PERFORMANCE_PASS_THROUGH_MIN_PERMILLE = 950',
    '$PERFORMANCE_OBSERVE_MIN_PERMILLE = 900',
    "@('baseline', 'pass_through', 'observe')",
    "@('pass_through', 'observe', 'baseline')",
    "@('observe', 'baseline', 'pass_through')",
    "@('baseline', 'observe', 'pass_through')",
    "@('pass_through', 'baseline', 'observe')",
    'Invoke-ExactProcess',
    'Get-ExactGreenDeploymentBundle',
    'SHA256SUMS',
    'manifest.json',
    'commit_sha',
    'Get-StableDeploymentRemoteState',
    'Wait-DeploymentRemoteState',
    'Assert-DeploymentRemoteStateUnchanged',
    'Register-DeploymentCleanup',
    'PowerShell.Exiting',
    'CancelKeyPress',
    'finally',
    'Assert-DeploymentCleanupTarget',
    'resolved-prefix',
    'identity-before-cleanup',
    'cleanup-generated-tree',
    'l2-loop-deploycheck',
    "'staging'",
    "'--bundle'",
    "'--root'",
    "'--json'",
    'staging_ready',
    'mutations_performed',
    'DG_ARTIFACT_INVENTORY',
    'DG_LAYOUT_TYPE',
    'DG_SYSTEMD_CONTRACT',
    'DG_AUTH_SCHEMA',
    'DG_AUTH_EXPIRED',
    'DG_PERFORMANCE_UNAVAILABLE',
    'pass-through-v1',
    'isolated-attach',
    'isolated-detach',
    'warm-up',
    'lower-median-of-five',
    'packets_per_second',
    'bytes_per_second',
    'daemon_cpu_time_ns',
    'peak_resident_memory_bytes',
    'packet_drop_delta',
    'packet_error_delta',
    'process_count_before',
    'map_count_before',
    'program_count_before',
    'pin_count_before',
    'namespace_count_before',
    'forwarding_intact',
    'owned_cleanup_complete',
    'network_identity_restored',
    'ebpf_identity_restored',
    'performance-v1.json',
    'deployment-v1.json',
    'PerformancePassThroughRegression',
    'PerformanceObserveRegression',
    'PerformanceDropError',
    'PerformanceIncomplete',
    'PerformanceIdentityMismatch',
    'PerformanceCleanupMismatch'
)) {
    Assert-True ($Harness.Contains($Required)) "deployment harness is missing required marker: $Required"
}

foreach ($Scenario in @(
    'Positive',
    'ChecksumMismatch',
    'ExtraFile',
    'Symlink',
    'WrongMode',
    'OccupiedRuntime',
    'MalformedAuthorization',
    'ExpiredAuthorization',
    'MalformedPerformance',
    'HardenedUnitFailure'
)) {
    Assert-True ($Harness.Contains("'$Scenario'")) "deployment harness is missing staging scenario: $Scenario"
}

foreach ($Forbidden in @(
    'strace',
    'apt-get',
    'apt ',
    'dnf ',
    'yum ',
    'zypper ',
    'systemctl',
    'journalctl',
    'sysctl',
    'modprobe',
    'insmod',
    'rmmod',
    'ethtool',
    'ovs-',
    'ip link set master',
    'default route',
    'Get-NetRoute',
    'pkill',
    'killall',
    'rm -rf',
    'rm -r ',
    'Invoke-Expression',
    'eval '
)) {
    Assert-True (-not $Harness.Contains($Forbidden)) "deployment harness contains forbidden text: $Forbidden"
}

Assert-True (-not [regex]::IsMatch($Harness, '(?m)^\s*param\([\s\S]*?\[string\]\s+\$Interface\b')) 'deployment harness exposes an interface parameter'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)^\s*ip\s+(?:addr|address|route)\s+(?:add|append|change|delete|del|flush|prepend|replace)\b')) 'deployment harness mutates addresses or routes'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)^\s*(?:while\s+(?::|true)|for\s*\(\s*;\s*;\s*\))')) 'deployment harness contains an unbounded loop'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)\b(?:Remove-Item|rm|unlink)\b[^\r\n]*[\*\?]')) 'deployment harness cleanup uses a wildcard target'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)^\s*(?:install|cp|mv|mkdir|chmod|chown)\b[^\r\n]*(?:\s|=)/(?:etc|usr|var)(?:/|\s|$)')) 'deployment harness writes a real production path'
Assert-True (-not [regex]::IsMatch($Harness, '(?m)ssh[^\r\n]*\$\(')) 'deployment harness SSH command uses command substitution'
Assert-True (-not [regex]::IsMatch($Harness, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')) 'deployment harness contains a hard-coded IPv4 target'
Assert-True (-not $Harness.Contains('.ssh')) 'deployment harness contains a hard-coded key path'
Assert-True ($Harness.Contains('cleanup_file "$root/checker.err"')) 'negative checker stderr is not included in failure-path cleanup'
Assert-True ($Harness.Contains('rebind_hardened_unit_fixture')) 'hardened-unit scenario does not preserve the preceding artifact/layout identities'
Assert-True ([regex]::IsMatch($Harness, '(?s)authorization = \{.*?"expires_at_unix_ms": now \+ 3600000\s*\}\s*orders = \[')) 'generated authorization fixture is not closed before performance trial construction'
Assert-True ($Harness.Contains('install -m 0755 "$bundle/l2-loop-hostcheck" "$root/l2-loop-hostcheck"')) 'pass-through hostcheck is not staged at its exact Task 9 artifact root'
Assert-True ($Harness.Contains('install -m 0644 "$bundle/l2-loop-ebpf.o" "$root/l2-loop-ebpf.o"')) 'pass-through eBPF object is not staged at its exact Task 9 artifact root'
$PassThroughStart = $Harness.IndexOf('start_pass_through() {')
$PassThroughStop = $Harness.IndexOf('stop_pass_through() {', $PassThroughStart)
Assert-True ($PassThroughStart -ge 0 -and $PassThroughStop -gt $PassThroughStart) 'pass-through lifecycle functions are missing or out of order'
if ($PassThroughStart -ge 0 -and $PassThroughStop -gt $PassThroughStart) {
    $PassThroughBody = $Harness.Substring($PassThroughStart, $PassThroughStop - $PassThroughStart)
    $Memlock = $PassThroughBody.IndexOf('ulimit -l unlimited')
    $Hostcheck = $PassThroughBody.IndexOf('"$root/l2-loop-hostcheck" pass-through')
    Assert-True ($Memlock -ge 0 -and $Hostcheck -gt $Memlock) 'pass-through does not raise its process memlock limit before preflight'
}
Assert-True ($Workflow.Contains('pwsh -NoProfile -File scripts/tests/verify-deployment-gates.Tests.ps1')) 'Linux CI does not run deployment harness safety tests'
Assert-True ($Workflow.Contains('powershell -NoProfile -File scripts/tests/verify-deployment-gates.Tests.ps1')) 'Windows CI does not run deployment harness safety tests'

if ($script:Failures -ne 0) {
    throw "$script:Failures deployment gate harness safety assertion(s) failed"
}

Write-Host 'deployment gate harness safety assertions passed'
