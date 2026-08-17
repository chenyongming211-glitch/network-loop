[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string] $RunId,

    [Parameter(Mandatory)]
    [string] $ServiceAuthorizationPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string] $InstallTransactionId,

    [ValidateRange(60, 900)]
    [int] $TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$MAX_OUTPUT_BYTES = 1048576
$SERVICE_CYCLE_COUNT = 2
$STOP_TIMEOUT_SECONDS = 10
$SOCKET_MODE = '600'
$SERVICE_WORK_PARENT = '/var/tmp/l2-loop-service-acceptance-v1'
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib/IsolatedNames.psm1')

$script:ServiceCleanupAction = $null
$script:ServiceCleanupComplete = $false

function Invoke-ExactServiceProcess {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $ArgumentList,
        [AllowNull()] [string] $StandardInput,
        [Parameter(Mandatory)] [int] $BoundSeconds,
        [switch] $AllowFailure
    )
    $StartInfo = [Diagnostics.ProcessStartInfo]::new()
    $StartInfo.FileName = $FilePath
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.RedirectStandardInput = $null -ne $StandardInput
    if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
        foreach ($Argument in $ArgumentList) { $null = $StartInfo.ArgumentList.Add($Argument) }
    }
    else {
        $StartInfo.Arguments = (($ArgumentList | ForEach-Object { ConvertTo-WindowsNativeArgument -Argument $_ }) -join ' ')
    }
    $Process = [Diagnostics.Process]::new()
    $Process.StartInfo = $StartInfo
    if (-not $Process.Start()) { throw "failed to start $FilePath" }
    if ($null -ne $StandardInput) {
        $Process.StandardInput.Write($StandardInput)
        $Process.StandardInput.Close()
    }
    $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
    $StderrTask = $Process.StandardError.ReadToEndAsync()
    if (-not $Process.WaitForExit($BoundSeconds * 1000)) {
        try { $Process.Kill($true) } catch { $Process.Kill() }
        throw "$FilePath exceeded the bounded timeout"
    }
    $Stdout = $StdoutTask.GetAwaiter().GetResult()
    $Stderr = $StderrTask.GetAwaiter().GetResult()
    if ([Text.Encoding]::UTF8.GetByteCount($Stdout) -gt $MAX_OUTPUT_BYTES -or
        [Text.Encoding]::UTF8.GetByteCount($Stderr) -gt $MAX_OUTPUT_BYTES) {
        throw "$FilePath exceeded the bounded output size"
    }
    if (-not $AllowFailure -and $Process.ExitCode -ne 0) {
        throw "$FilePath failed with exit code $($Process.ExitCode): $Stderr"
    }
    [pscustomobject]@{ ExitCode = $Process.ExitCode; Stdout = $Stdout; Stderr = $Stderr }
}

function Get-RequiredEnvironment {
    param([Parameter(Mandatory)] [string] $Name)
    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Name must be set explicitly" }
    $Value
}

function Get-LocalSha256 {
    param([Parameter(Mandatory)] [string] $Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-StrictServiceAuthorization {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ArtifactCommit,
        [Parameter(Mandatory)] [string] $HostIdentity,
        [Parameter(Mandatory)] [string] $TransactionId
    )
    $Item = Get-Item -LiteralPath $Path
    if ($Item.PSIsContainer -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'service authorization must be one regular local file'
    }
    if ($Item.Length -gt 16384) { throw 'service authorization exceeds its size bound' }
    $Authorization = Get-Content -LiteralPath $Item.FullName -Raw | ConvertFrom-Json
    $ExpectedFields = @(
        'artifact_commit_sha', 'authorization_id', 'cycle_count', 'expires_at_unix_ms',
        'generated_only', 'host_identity_sha256', 'install_transaction_id',
        'issued_at_unix_ms', 'operation', 'physical_attach', 'schema_version',
        'service_enable', 'stop_timeout_seconds'
    ) | Sort-Object
    if ((@($Authorization.PSObject.Properties.Name | Sort-Object) -join ',') -cne ($ExpectedFields -join ',')) {
        throw 'service authorization schema is not exact'
    }
    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    if ([int]$Authorization.schema_version -ne 1 -or
        [string]$Authorization.operation -cne 'service_acceptance' -or
        [string]$Authorization.authorization_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Authorization.artifact_commit_sha -cne $ArtifactCommit -or
        [string]$Authorization.host_identity_sha256 -cne $HostIdentity -or
        [string]$Authorization.install_transaction_id -cne $TransactionId -or
        [int64]$Authorization.issued_at_unix_ms -gt $Now -or
        [int64]$Authorization.expires_at_unix_ms -le $Now -or
        ([int64]$Authorization.expires_at_unix_ms - [int64]$Authorization.issued_at_unix_ms) -gt 3600000 -or
        [bool]$Authorization.service_enable -or [bool]$Authorization.physical_attach -or
        -not [bool]$Authorization.generated_only -or
        [int]$Authorization.cycle_count -ne $SERVICE_CYCLE_COUNT -or
        [int]$Authorization.stop_timeout_seconds -ne $STOP_TIMEOUT_SECONDS) {
        throw 'service authorization binding or safety flags are invalid'
    }
    $Authorization
}

function New-ServiceAcceptanceNames {
    param([Parameter(Mandatory)] [string] $GeneratedRunId)
    $ProbeBytes = [byte[]]::new(16)
    $Generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $Generator.GetBytes($ProbeBytes) } finally { $Generator.Dispose() }
    $Names = New-IsolatedNames -RunId $GeneratedRunId
    [pscustomobject]@{
        RunId = $Names.RunId
        Namespace = $Names.Namespace
        HostVeth = $Names.HostVeth
        PeerVeth = $Names.PeerVeth
        WorkRoot = "$SERVICE_WORK_PARENT/$GeneratedRunId"
        RuntimeRoot = $Names.RemoteRunRoot
        Socket = '/run/l2-loop/agent.sock'
        ControllerNonce = -join ($ProbeBytes | ForEach-Object { $_.ToString('x2') })
    }
}

function Assert-ServiceCleanupTarget {
    param([Parameter(Mandatory)] [psobject] $Names)
    Assert-IsolatedRunId -RunId $Names.RunId
    if ($Names.WorkRoot -cne "$SERVICE_WORK_PARENT/$($Names.RunId)" -or
        $Names.RuntimeRoot -cne "/run/l2-loop/accept/$($Names.RunId)" -or
        $Names.Namespace -cne "l2ns-$($Names.RunId.Substring(0, 12))" -or
        $Names.HostVeth -cne "l2h$($Names.RunId.Substring(0, 10))" -or
        $Names.PeerVeth -cne "l2n$($Names.RunId.Substring(0, 10))") {
        throw 'service cleanup identity is not the active generated run'
    }
}

function Register-ServiceCleanup {
    param([Parameter(Mandatory)] [scriptblock] $Action)
    $script:ServiceCleanupAction = $Action
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($null -ne $script:ServiceCleanupAction -and -not $script:ServiceCleanupComplete) {
            & $script:ServiceCleanupAction
        }
    }
}

function Unregister-ServiceCleanup {
    param([Parameter(Mandatory)] [ConsoleCancelEventHandler] $CancelHandler)
    [Console]::remove_CancelKeyPress($CancelHandler)
    Unregister-Event -SourceIdentifier PowerShell.Exiting -ErrorAction SilentlyContinue
    $script:ServiceCleanupAction = $null
}

$RemoteServiceProgram = @'
set -Eeuo pipefail
phase=$1
run=$2
ns=$3
host=$4
peer=$5
work=$6
runtime=$7
auth=$8
cycle=$9
stop_bound=${10}
socket=/run/l2-loop/agent.sock
unit=l2-loop.service
work_parent=/var/tmp/l2-loop-service-acceptance-v1
ctl=/usr/bin/l2-loopctl
daemon=/usr/libexec/l2-loop/l2-loopd
trap 'code=$?; printf "service phase failed: phase=%s line=%s code=%s\n" "$phase" "$LINENO" "$code" >&2; exit "$code"' ERR

fail() { printf '%s\n' "$1" >&2; exit 1; }
assert_generated() {
    case "$run" in *[!0-9a-f]*|'') fail 'invalid generated run' ;; esac
    test "${#run}" -eq 32 || fail 'invalid generated run length'
    test "$work" = "/var/tmp/l2-loop-service-acceptance-v1/$run" || fail 'invalid work root'
    test "$runtime" = "/run/l2-loop/accept/$run" || fail 'invalid runtime root'
    test "$ns" = "l2ns-${run:0:12}" || fail 'invalid namespace'
    test "$host" = "l2h${run:0:10}" || fail 'invalid host veth'
    test "$peer" = "l2n${run:0:10}" || fail 'invalid peer veth'
}
snapshot() {
    python3 - "$run" <<'PY'
import hashlib,json,subprocess,sys
run=sys.argv[1]
def get(argv):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    if len(p.stdout)>1048576: raise SystemExit('snapshot output bound exceeded')
    return p.stdout
parts=[]
for argv in (['ip','-j','link','show'],['bpftool','-j','prog','show'],['bpftool','-j','map','show'],['bpftool','-j','link','show'],['ip','netns','list']):
    parts.append(get(argv))
print(json.dumps({'network':hashlib.sha256(parts[0]+b'\0'+parts[4]).hexdigest(),'ebpf':hashlib.sha256(b'\0'.join(parts[1:4])).hexdigest(),'run':run},separators=(',',':')))
PY
}
cleanup_generated() {
    if test -f "$work/service-started"; then
        systemctl stop "$unit" || true
        wait_inactive
        unlink -- "$work/service-started"
    fi
    if test -f "$runtime/fallback.pid"; then
        pid=$(cat -- "$runtime/fallback.pid")
        case "$pid" in *[!0-9]*|'') fail 'fallback PID identity is invalid' ;; esac
        if test -e "/proc/$pid/exe" && test "$(readlink -f -- "/proc/$pid/exe")" = "$daemon"; then kill -TERM "$pid"; fi
    fi
    if ip netns list | awk '{print $1}' | grep -Fxq -- "$ns"; then ip netns exec "$ns" ip link set lo down; ip netns delete "$ns"; fi
    if ip link show dev "$host" >/dev/null 2>&1; then ip link delete "$host"; fi
    if test -S "$socket" && test "$(systemctl is-active "$unit" 2>/dev/null || true)" = inactive; then unlink -- "$socket"; fi
    if test -d "$runtime"; then
        test ! -L "$runtime" || fail 'runtime root became a link'
        for leaf in fallback.pid fallback.stderr fallback.stdout service-authorization.json; do test ! -e "$runtime/$leaf" || unlink -- "$runtime/$leaf"; done
        test ! -d "$runtime/evidence/v1" || rmdir -- "$runtime/evidence/v1"
        test ! -d "$runtime/evidence" || rmdir -- "$runtime/evidence"
        rmdir -- "$runtime"
    fi
    if test -d "$work"; then
        test ! -L "$work" || fail 'work root became a link'
        for leaf in service-authorization.json service-started journal-before journal-after cycle-1.json cycle-2.json; do test ! -e "$work/$leaf" || unlink -- "$work/$leaf"; done
        rmdir -- "$work"
    fi
}
wait_inactive() {
    deadline=$(( $(date +%s) + stop_bound ))
    while test "$(systemctl is-active "$unit" 2>/dev/null || true)" != inactive; do
        test "$(date +%s)" -lt "$deadline" || fail 'service stop bound exceeded'
        sleep 1
    done
}
assert_generated
case "$phase" in
precheck)
    test "$(id -u)" -eq 0 || fail 'service acceptance requires root'
    for name in systemctl journalctl ip bpftool python3 sha256sum awk grep stat install chmod unlink rmdir mkdir sleep date kill; do command -v "$name" >/dev/null || fail 'required command unavailable'; done
    test -x "$ctl" && test -x "$daemon" && test -f /usr/lib/systemd/system/l2-loop.service || fail 'installed service layout incomplete'
    test ! -e "$work" && test ! -e "$runtime" || fail 'generated service root occupied'
    install -d -m 0700 -- "$work_parent" "$work"
    ;;
prior-unit)
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    active=$(systemctl is-active "$unit" 2>/dev/null || true)
    test "$enabled" = disabled || fail 'unit was not disabled before acceptance'
    test "$active" = inactive || fail 'unit was not inactive before acceptance'
    test ! -S "$socket" || fail 'runtime socket was already present'
    printf '{"enabled":"%s","active":"%s"}\n' "$enabled" "$active"
    ;;
snapshot) snapshot ;;
daemon-reload) systemctl daemon-reload ;;
journal-cursor)
    journalctl --quiet --show-cursor -n 0 -o cat | sed -n 's/^-- cursor: //p'
    ;;
start)
    systemctl start "$unit"
    printf 'owned\n' >"$work/service-started"
    deadline=$(( $(date +%s) + 10 ))
    while test ! -S "$socket"; do test "$(date +%s)" -lt "$deadline" || fail 'root socket did not appear'; sleep 1; done
    test "$(stat -c %u -- "$socket")" = 0 || fail 'socket owner is not root'
    test "$(stat -c %a -- "$socket")" = 600 || fail 'socket mode is not 600'
    printf '{"root_socket_verified":true}\n'
    ;;
exercise)
    test -S "$socket" || fail 'service socket unavailable'
    ip netns add "$ns"
    ip link add "$host" type veth peer name "$peer"
    ip link set "$peer" netns "$ns"
    ip link set "$host" up
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "$peer" up
    "$ctl" isolated-attach --interface "$host" --run-id "$run" >/dev/null
    "$ctl" observe --interface "$host" >/dev/null
    "$ctl" observe --interface "$host" --json >"$work/cycle-$cycle.json"
    "$ctl" status --interface "$host" >/dev/null
    "$ctl" status --interface "$host" --json >/dev/null
    "$ctl" isolated-detach --run-id "$run" >/dev/null
    ip netns exec "$ns" ip link set lo down
    ip netns delete "$ns"
    test ! -e "/sys/fs/bpf/l2-loop/test/$run" || fail 'owned pin residue remains'
    ;;
stop)
    systemctl stop "$unit"
    wait_inactive
    unlink -- "$work/service-started"
    test ! -S "$socket" || fail 'service socket remains after stop'
    printf '{"inactive":true}\n'
    ;;
journal)
    before=$(cat -- "$work/journal-before")
    journalctl --quiet --after-cursor "$before" '_SYSTEMD_UNIT=l2-loop.service' -o json --no-pager >"$work/journal-after"
    cat -- "$work/journal-after"
    ;;
fallback)
    install -d -m 0700 -- "$runtime" "$runtime/evidence" "$runtime/evidence/v1"
    env L2_LOOP_ACCEPTANCE_EVIDENCE_ROOT="$runtime/evidence/v1" "$daemon" >"$runtime/fallback.stdout" 2>"$runtime/fallback.stderr" &
    pid=$!
    printf '%s\n' "$pid" >"$runtime/fallback.pid"
    deadline=$(( $(date +%s) + 10 ))
    while test ! -S "$socket"; do test "$(date +%s)" -lt "$deadline" || fail 'fallback socket did not appear'; sleep 1; done
    kill -TERM "$pid"
    wait "$pid"
    test -d "$runtime/evidence/v1" || fail 'acceptance evidence root did not persist'
    test -f "$runtime/fallback.stderr" || fail 'fallback stderr capture missing'
    ;;
cleanup) cleanup_generated ;;
residue)
    count=0
    for candidate in "$work" "$runtime" "/sys/fs/bpf/l2-loop/test/$run"; do test ! -e "$candidate" || count=$((count+1)); done
    ip netns list | awk '{print $1}' | grep -Fxq -- "$ns" && count=$((count+1)) || true
    ip link show dev "$host" >/dev/null 2>&1 && count=$((count+1)) || true
    printf '%s\n' "$count"
    ;;
*) fail 'unknown service acceptance phase' ;;
esac
'@

function Invoke-ServiceRemotePhase {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [int] $Cycle = 0,
        [switch] $AllowFailure
    )
    Assert-ServiceCleanupTarget -Names $Names
    $RemoteArguments = @('bash', '-s', '--', $Phase, $Names.RunId, $Names.Namespace, $Names.HostVeth, $Names.PeerVeth, $Names.WorkRoot, $Names.RuntimeRoot, "$($Names.WorkRoot)/service-authorization.json", [string]$Cycle, [string]$STOP_TIMEOUT_SECONDS)
    $Arguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments $RemoteArguments
    Invoke-ExactServiceProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $RemoteServiceProgram -BoundSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Invoke-ServiceCommand {
    param(
        [Parameter(Mandatory)] [string] $Command,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath
    )
    if ($Command -cnotin @("daemon-reload", "start", "stop")) { throw 'service command is outside the fixed vocabulary' }
    Invoke-ServiceRemotePhase -Phase $Command -Names $Names -Target $Target -KeyPath $KeyPath
}

function Get-PriorUnitState {
    param([psobject] $Names, [string] $Target, [string] $KeyPath)
    (Invoke-ServiceRemotePhase -Phase 'prior-unit' -Names $Names -Target $Target -KeyPath $KeyPath).Stdout | ConvertFrom-Json
}

function Get-StableServiceHostState {
    param([psobject] $Names, [string] $Target, [string] $KeyPath)
    ((Invoke-ServiceRemotePhase -Phase 'snapshot' -Names $Names -Target $Target -KeyPath $KeyPath).Stdout.Trim() | ConvertFrom-Json)
}

function Wait-StableServiceHostState {
    param([psobject] $Names, [string] $Target, [string] $KeyPath)
    $Previous = $null
    for ($Attempt = 0; $Attempt -lt 12; $Attempt++) {
        $Current = Get-StableServiceHostState -Names $Names -Target $Target -KeyPath $KeyPath
        $Canonical = $Current | ConvertTo-Json -Compress
        if ($Canonical -ceq $Previous) { return $Current }
        $Previous = $Canonical
        Start-Sleep -Milliseconds 250
    }
    throw 'network and eBPF state did not converge'
}

function Assert-ServiceHostStateUnchanged {
    param([psobject] $Before, [psobject] $After)
    if ($Before.network -cne $After.network -or $Before.ebpf -cne $After.ebpf) {
        throw 'network or eBPF identity changed across service acceptance'
    }
}

function Wait-ServiceInactive {
    param([psobject] $Names, [string] $Target, [string] $KeyPath)
    $State = Get-PriorUnitState -Names $Names -Target $Target -KeyPath $KeyPath
    if ($State.active -cne 'inactive') { throw 'service did not become inactive' }
    $State
}

function Assert-SanitizedJournalRecords {
    param([Parameter(Mandatory)] [string] $JsonLines)
    if ([Text.Encoding]::UTF8.GetByteCount($JsonLines) -gt $MAX_OUTPUT_BYTES) { throw 'journal output exceeds bound' }
    $ProhibitedFields = @('INTERFACE', 'MAC', 'SOURCE_IP', 'DESTINATION_IP', 'PACKET', 'PAYLOAD')
    foreach ($Line in @($JsonLines -split "`r?`n" | Where-Object { $_.Length -ne 0 })) {
        $Record = $Line | ConvertFrom-Json
        foreach ($Name in $Record.PSObject.Properties.Name) {
            if ($Name.ToUpperInvariant() -in $ProhibitedFields) { throw 'journal record contains a prohibited traffic identity field' }
        }
        if ([string]$Record._SYSTEMD_UNIT -cne 'l2-loop.service') { throw 'journal record escaped the exact unit cursor query' }
    }
}

function Start-InjectedFallbackDaemon {
    param([psobject] $Names, [string] $Target, [string] $KeyPath)
    Invoke-ServiceRemotePhase -Phase 'fallback' -Names $Names -Target $Target -KeyPath $KeyPath
}

function Invoke-ServiceCleanup {
    param([psobject] $Names, [string] $Target, [string] $KeyPath)
    $null = Invoke-ServiceRemotePhase -Phase 'cleanup' -Names $Names -Target $Target -KeyPath $KeyPath -AllowFailure
}

$Target = Get-RequiredEnvironment -Name 'L2_LOOP_TEST_TARGET'
$KeyPath = Get-RequiredEnvironment -Name 'L2_LOOP_TEST_KEY'
$Names = New-ServiceAcceptanceNames -GeneratedRunId $RunId
$HostIdentity = (Invoke-ExactServiceProcess -FilePath 'ssh' -ArgumentList (Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @('sha256sum', '/etc/machine-id')) -StandardInput $null -BoundSeconds 30).Stdout.Split(' ')[0].Trim()
$Authorization = Assert-StrictServiceAuthorization -Path $ServiceAuthorizationPath -ArtifactCommit $Commit -HostIdentity $HostIdentity -TransactionId $InstallTransactionId
$AuthorizationSha256 = Get-LocalSha256 -Path $ServiceAuthorizationPath

$CleanupAction = { Invoke-ServiceCleanup -Names $Names -Target $Target -KeyPath $KeyPath }
Register-ServiceCleanup -Action $CleanupAction
$CancelHandler = [ConsoleCancelEventHandler]{
    param($Sender, $EventArgs)
    $EventArgs.Cancel = $true
    if ($null -ne $script:ServiceCleanupAction -and -not $script:ServiceCleanupComplete) { & $script:ServiceCleanupAction }
}
[Console]::add_CancelKeyPress($CancelHandler)

try {
    $null = Invoke-ServiceRemotePhase -Phase 'precheck' -Names $Names -Target $Target -KeyPath $KeyPath
    $ScpArguments = Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources @((Resolve-Path -LiteralPath $ServiceAuthorizationPath).Path) -Destination "$($Names.WorkRoot)/service-authorization.json"
    $null = Invoke-ExactServiceProcess -FilePath 'scp' -ArgumentList $ScpArguments -StandardInput $null -BoundSeconds 60
    $PriorUnitState = Get-PriorUnitState -Names $Names -Target $Target -KeyPath $KeyPath
    if ($PriorUnitState.enabled -cne 'disabled' -or $PriorUnitState.active -cne 'inactive') { throw 'prior unit state is not acceptable' }
    $BeforeState = Wait-StableServiceHostState -Names $Names -Target $Target -KeyPath $KeyPath
    $ReadOnlyUnitStates = @('is-enabled', 'is-active', 'disabled', 'inactive')
    $JournalQueryVocabulary = @('--after-cursor', '_SYSTEMD_UNIT=l2-loop.service', 'json')
    $ControlVocabulary = @('isolated-attach', 'isolated-detach', 'observe', 'status', '--json')
    $JournalCursorBefore = (Invoke-ServiceRemotePhase -Phase 'journal-cursor' -Names $Names -Target $Target -KeyPath $KeyPath).Stdout.Trim()
    if ([string]::IsNullOrWhiteSpace($JournalCursorBefore) -or $JournalCursorBefore.Length -gt 4096) { throw 'journal cursor is invalid' }
    $CursorUpload = Invoke-ExactServiceProcess -FilePath 'ssh' -ArgumentList (Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @('tee', "$($Names.WorkRoot)/journal-before")) -StandardInput $JournalCursorBefore -BoundSeconds 30

    $ReloadResult = Invoke-ServiceCommand -Command 'daemon-reload' -Names $Names -Target $Target -KeyPath $KeyPath
    $CycleEvidence = @()
    for ($Cycle = 1; $Cycle -le $SERVICE_CYCLE_COUNT; $Cycle++) {
        $StartResult = Invoke-ServiceCommand -Command 'start' -Names $Names -Target $Target -KeyPath $KeyPath
        $SocketEvidence = $StartResult.Stdout | ConvertFrom-Json
        if (-not [bool]$SocketEvidence.root_socket_verified) { throw 'root socket verification failed' }
        $null = Invoke-ServiceRemotePhase -Phase 'exercise' -Names $Names -Target $Target -KeyPath $KeyPath -Cycle $Cycle
        $StopResult = Invoke-ServiceCommand -Command 'stop' -Names $Names -Target $Target -KeyPath $KeyPath
        $null = Wait-ServiceInactive -Names $Names -Target $Target -KeyPath $KeyPath
        $CycleEvidence += [ordered]@{ cycle = $Cycle; root_socket_verified = $true; stopped_within_bound = $true }
    }

    $JournalResult = Invoke-ServiceRemotePhase -Phase 'journal' -Names $Names -Target $Target -KeyPath $KeyPath
    Assert-SanitizedJournalRecords -JsonLines $JournalResult.Stdout
    $JournalCursorAfter = (Invoke-ServiceRemotePhase -Phase 'journal-cursor' -Names $Names -Target $Target -KeyPath $KeyPath).Stdout.Trim()
    $Fallback = Start-InjectedFallbackDaemon -Names $Names -Target $Target -KeyPath $KeyPath
    $AfterState = Wait-StableServiceHostState -Names $Names -Target $Target -KeyPath $KeyPath
    Assert-ServiceHostStateUnchanged -Before $BeforeState -After $AfterState
    Invoke-ServiceCleanup -Names $Names -Target $Target -KeyPath $KeyPath
    $script:ServiceCleanupComplete = $true
    $ResidueCount = [int](Invoke-ServiceRemotePhase -Phase 'residue' -Names $Names -Target $Target -KeyPath $KeyPath).Stdout.Trim()
    if ($ResidueCount -ne 0) { throw 'generated service residue remains' }

    [ordered]@{
        schema_version = 1
        decision = 'service_verified'
        artifact_commit_sha = $Commit
        authorization_id = [string]$Authorization.authorization_id
        authorization_sha256 = $AuthorizationSha256
        install_transaction_id = $InstallTransactionId
        service_cycle_count = $SERVICE_CYCLE_COUNT
        stop_timeout_seconds = $STOP_TIMEOUT_SECONDS
        socket_mode = $SOCKET_MODE
        root_socket_verified = $true
        journal_cursor_before = $JournalCursorBefore
        journal_cursor_after = $JournalCursorAfter
        sanitized_journal_records = $true
        stderr_fallback_verified = $true
        evidence_persistence_verified = $true
        network_identity_before = [string]$BeforeState.network
        network_identity_after = [string]$AfterState.network
        ebpf_identity_before = [string]$BeforeState.ebpf
        ebpf_identity_after = [string]$AfterState.ebpf
        owned_cleanup_complete = $true
        generated_residue_count = $ResidueCount
        service_enable = $false
        mutations_performed = $true
        cycles = $CycleEvidence
    } | ConvertTo-Json -Depth 8 -Compress
}
finally {
    if (-not $script:ServiceCleanupComplete) { try { & $CleanupAction } catch { Write-Warning $_.Exception.Message } }
    Unregister-ServiceCleanup -CancelHandler $CancelHandler
}
