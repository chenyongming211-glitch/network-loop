[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [ValidateRange(1, 256)]
    [int] $FrameCount = 32,

    [ValidateRange(30, 600)]
    [int] $TimeoutSeconds = 180,

    [ValidateSet('Success', 'TcAttachFailure', 'MapInitializeFailure', 'DaemonTermination', 'IdentityChange', 'TrafficInterruption')]
    [string] $Scenario = 'Success'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib/IsolatedNames.psm1') -Force

$ExpectedBundleFiles = @(
    'l2-loopd',
    'l2-loopctl',
    'l2-loop-hostcheck',
    'l2-loop-ebpf.o',
    'manifest.json',
    'SHA256SUMS'
)

function Invoke-ExactProcess {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $ArgumentList,
        [AllowNull()] [string] $StandardInput,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [switch] $AllowFailure
    )

    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $StartInfo.FileName = $FilePath
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.RedirectStandardInput = $null -ne $StandardInput
    if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
        foreach ($Argument in $ArgumentList) {
            $null = $StartInfo.ArgumentList.Add($Argument)
        }
    }
    else {
        $StartInfo.Arguments = (($ArgumentList | ForEach-Object {
            ConvertTo-WindowsNativeArgument -Argument $_
        }) -join ' ')
    }

    $Process = [System.Diagnostics.Process]::new()
    $Process.StartInfo = $StartInfo
    if (-not $Process.Start()) {
        throw "failed to start $FilePath"
    }
    if ($null -ne $StandardInput) {
        try {
            $Process.StandardInput.Write($StandardInput)
            $Process.StandardInput.Close()
        }
        catch [System.IO.IOException] {
            $Process.WaitForExit()
            $StdinError = $Process.StandardError.ReadToEnd()
            throw "$FilePath closed standard input before the bounded request completed: $StdinError"
        }
    }
    $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
    $StderrTask = $Process.StandardError.ReadToEndAsync()
    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $Process.Kill($true) } catch { $Process.Kill() }
        throw "$FilePath exceeded the bounded timeout"
    }
    $Stdout = $StdoutTask.GetAwaiter().GetResult()
    $Stderr = $StderrTask.GetAwaiter().GetResult()
    if (-not $AllowFailure -and $Process.ExitCode -ne 0) {
        throw "$FilePath failed with exit code $($Process.ExitCode): $Stderr"
    }
    [pscustomobject]@{
        ExitCode = $Process.ExitCode
        Stdout = $Stdout
        Stderr = $Stderr
    }
}

function Assert-NoSymlink {
    param([Parameter(Mandatory)] [System.IO.FileSystemInfo] $Item)

    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'symbolic links are forbidden for local acceptance inputs'
    }
}

function Assert-GeneratedTarget {
    param([Parameter(Mandatory)] [psobject] $Names)

    Assert-CleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot
}

function Get-ExactGreenBundle {
    param([Parameter(Mandatory)] [string] $Commit)

    $RunQuery = Invoke-ExactProcess -FilePath 'gh' -ArgumentList @(
        'run', 'list', '--branch', 'main', '--commit', $Commit, '--limit', '10',
        '--json', 'databaseId,conclusion,headSha'
    ) -TimeoutSeconds 60
    $Run = @($RunQuery.Stdout | ConvertFrom-Json) |
        Where-Object { $null -ne $_ -and $_.headSha -ceq $Commit -and $_.conclusion -ceq 'success' } |
        Select-Object -First 1
    if ($null -eq $Run) {
        throw 'the exact commit does not have a successful GitHub Actions run'
    }

    $ArtifactRoot = Join-Path $RepositoryRoot ".artifacts/$Commit"
    if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
        $null = Invoke-ExactProcess -FilePath 'gh' -ArgumentList @(
            'run', 'download', [string]$Run.databaseId,
            '--name', "l2-loop-linux-x86_64-$Commit",
            '--dir', $ArtifactRoot
        ) -TimeoutSeconds 120
    }

    $RootItem = Get-Item -LiteralPath $ArtifactRoot
    Assert-NoSymlink -Item $RootItem
    foreach ($Filename in $ExpectedBundleFiles) {
        $Path = Join-Path $ArtifactRoot $Filename
        $Item = Get-Item -LiteralPath $Path
        Assert-NoSymlink -Item $Item
        if (-not $Item.PSIsContainer -and $Item.Name -cne $Filename) {
            throw 'bundle filename changed identity'
        }
    }

    $ChecksumLines = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'SHA256SUMS')
    if ($ChecksumLines.Count -ne 5) {
        throw 'bundle checksum file must contain exactly five entries'
    }
    foreach ($Line in $ChecksumLines) {
        if ($Line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') {
            throw 'bundle checksum line is malformed'
        }
        $ExpectedHash = $Matches[1]
        $Filename = $Matches[2]
        if ($Filename -cnotin $ExpectedBundleFiles) {
            throw 'bundle checksum covers an unexpected file'
        }
        $ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ArtifactRoot $Filename)).Hash.ToLowerInvariant()
        if ($ActualHash -cne $ExpectedHash) {
            throw "bundle checksum mismatch for $Filename"
        }
    }
    $Manifest = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'manifest.json') -Raw | ConvertFrom-Json
    if ($Manifest.commit_sha -cne $Commit) {
        throw 'bundle manifest commit does not match the requested commit'
    }
    $ArtifactRoot
}

$RemoteProgram = @'
set -eu

phase=$1
run=$2
ns=$3
host=$4
peer=$5
root=$6
count=$7
scenario=$8
journal="/run/l2-loop/tests/$run.json"
pins="/sys/fs/bpf/l2-loop/test/$run"
saved_journal="$root/ownership.original.json"
changed_journal="$root/ownership.changed.json"

fail() { printf '%s\n' "$1" >&2; exit 1; }
assert_no_symlink() { test ! -L "$1" || fail "owned path is a symbolic link"; }
assert_generated() {
    test "$(printf '%.12s' "$run")" = "${ns#l2ns-}" || fail "namespace is not generated"
    test "$(printf '%.10s' "$run")" = "${host#l2h}" || fail "host veth is not generated"
    test "$(printf '%.10s' "$run")" = "${peer#l2n}" || fail "peer veth is not generated"
    test "$root" = "/run/l2-loop/accept/$run" || fail "run root is not generated"
}
assert_generated
case "$scenario" in
    Success|TcAttachFailure|MapInitializeFailure|DaemonTermination|IdentityChange|TrafficInterruption) ;;
    *) fail "unknown isolated acceptance scenario" ;;
esac

snapshot() {
    {
        "$root/l2-loop-hostcheck" snapshot
        ip -j link show
        ip -j route show table all
    } | sha256sum | awk '{print $1}'
}

cleanup_file() {
    path=$1
    if test -e "$path" || test -L "$path"; then
        assert_no_symlink "$path"
        unlink "$path"
    fi
}

cleanup_dir() {
    path=$1
    if test -d "$path" || test -L "$path"; then
        assert_no_symlink "$path"
        rmdir "$path"
    fi
}

stop_daemon() {
    if test -f "$root/daemon.pid" && test ! -L "$root/daemon.pid"; then
        pid=$(cat "$root/daemon.pid")
        case "$pid" in *[!0-9]*|'') fail "invalid owned daemon PID" ;; esac
        if test -e "/proc/$pid/exe"; then
            exe=$(readlink "/proc/$pid/exe")
            test "$exe" = "$root/l2-loopd" || fail "daemon PID identity changed"
            kill -TERM "$pid"
            tries=0
            while kill -0 "$pid" 2>/dev/null && test "$tries" -lt 50; do
                sleep 0.1
                tries=$((tries + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || printf unknown)
                fail "owned daemon did not stop: process state $state"
            fi
        fi
    fi
}

cleanup_state() {
    stop_daemon

    if ip link show dev "$host" >/dev/null 2>&1; then
        kind=$(ip -j -details link show dev "$host" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0].get("linkinfo",{}).get("info_kind",""))')
        test "$kind" = veth || fail "generated host target is not a veth"
        ip link delete dev "$host"
    fi
    if ip netns list | awk '{print $1}' | grep -Fqx -- "$ns"; then
        if ip netns exec "$ns" ip link show dev "$peer" >/dev/null 2>&1; then
            kind=$(ip netns exec "$ns" ip -j -details link show dev "$peer" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0].get("linkinfo",{}).get("info_kind",""))')
            test "$kind" = veth || fail "generated peer target is not a veth"
        fi
        ip netns delete "$ns"
    fi

    for name in IFACE_CONFIG HOOK_STATS FINGERPRINTS PROBE_REGISTRY PROBE_STATS RATE_POLICY; do
        cleanup_file "$pins/$name"
    done
    cleanup_dir "$pins"
    cleanup_file "$journal"
    cleanup_file "$root/counters.json"
    cleanup_file "$saved_journal"
    cleanup_file "$changed_journal"
    cleanup_file "$root/daemon.pid"
    cleanup_file "$root/daemon.log"
    cleanup_dir /sys/fs/bpf/l2-loop/test
    cleanup_dir /sys/fs/bpf/l2-loop
    cleanup_dir /run/l2-loop/tests
}

cleanup() {
    cleanup_state
    cleanup_file "$root/l2-loopd"
    cleanup_file "$root/l2-loopctl"
    cleanup_file "$root/l2-loop-hostcheck"
    cleanup_file "$root/l2-loop-ebpf.o"
    cleanup_file "$root/manifest.json"
    cleanup_file "$root/SHA256SUMS"
    cleanup_dir "$root"
    cleanup_dir /run/l2-loop/accept
    cleanup_dir /run/l2-loop
}

case "$phase" in
    precheck)
        for command_name in ip python3 sha256sum awk grep mkdir rmdir install chmod readlink kill sleep cat unlink env mv; do
            command -v "$command_name" >/dev/null || fail "required acceptance command is unavailable"
        done
        test ! -e /run/l2-loop && test ! -L /run/l2-loop || fail "agent runtime root is already occupied"
        test ! -e /sys/fs/bpf/l2-loop && test ! -L /sys/fs/bpf/l2-loop || fail "agent pin root is already occupied"
        test ! -e "$root" && test ! -L "$root" || fail "run root already exists"
        test ! -e "$journal" && test ! -L "$journal" || fail "run journal already exists"
        test ! -e "$saved_journal" && test ! -L "$saved_journal" || fail "saved journal already exists"
        test ! -e "$changed_journal" && test ! -L "$changed_journal" || fail "changed journal already exists"
        test ! -e "$pins" && test ! -L "$pins" || fail "run pin root already exists"
        ! ip link show dev "$host" >/dev/null 2>&1 || fail "generated host veth already exists"
        ! ip netns list | awk '{print $1}' | grep -Fqx -- "$ns" || fail "generated namespace already exists"
        test ! -e /run/l2-loop/agent.sock && test ! -L /run/l2-loop/agent.sock || fail "daemon socket is already occupied"
        ;;
    snapshot)
        snapshot
        ;;
    stage)
        install -d -m 0700 /run/l2-loop
        install -d -m 0700 /run/l2-loop/accept
        install -d -m 0700 "$root"
        ;;
    prepare)
        ip netns add "$ns"
        ip link add name "$host" type veth peer name "$peer"
        ip link set dev "$peer" netns "$ns"
        ;;
    install)
        assert_no_symlink "$root"
        cd "$root"
        sha256sum --check SHA256SUMS >/dev/null
        chmod 0755 l2-loopd l2-loopctl l2-loop-hostcheck
        ;;
    launch)
        cd "$root"
        ulimit -l unlimited
        case "$scenario" in
            TcAttachFailure)
                env L2_LOOP_ACCEPTANCE_FAULT=tc-attach ./l2-loopd >daemon.log 2>&1 &
                ;;
            MapInitializeFailure)
                env L2_LOOP_ACCEPTANCE_FAULT=map-initialize ./l2-loopd >daemon.log 2>&1 &
                ;;
            *)
                ./l2-loopd >daemon.log 2>&1 &
                ;;
        esac
        printf '%s\n' "$!" >daemon.pid
        tries=0
        while test ! -S /run/l2-loop/agent.sock && test "$tries" -lt 50; do
            sleep 0.1
            tries=$((tries + 1))
        done
        test -S /run/l2-loop/agent.sock || fail "daemon socket was not created"
        ;;
    verify-hooks)
        "$root/l2-loop-hostcheck" 'verify-owned' --journal "$journal" --interface "$host"
        ;;
    verify-hooks-saved)
        "$root/l2-loop-hostcheck" 'verify-owned' --journal "$saved_journal" --interface "$host"
        ;;
    links-up)
        ip link set dev "$host" up
        ip netns exec "$ns" ip link set dev "$peer" up
        ;;
    links-down)
        ip link set dev "$host" down
        ip netns exec "$ns" ip link set dev "$peer" down
        ;;
    counters)
        "$root/l2-loop-hostcheck" 'counters' --journal "$journal"
        ;;
    traffic)
        python3 - "$host" "$count" <<'PY'
import socket, sys
interface, count = sys.argv[1], int(sys.argv[2])
frame = bytes.fromhex("ffffffffffff02000000000188b5") + bytes(46)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as channel:
    channel.bind((interface, 0))
    for _ in range(count):
        channel.send(frame)
PY
        ip netns exec "$ns" python3 - "$peer" "$count" <<'PY'
import socket, sys
interface, count = sys.argv[1], int(sys.argv[2])
frame = bytes.fromhex("ffffffffffff02000000000288b5") + bytes(46)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as channel:
    channel.bind((interface, 0))
    for _ in range(count):
        channel.send(frame)
PY
        ;;
    traffic-interrupt)
        python3 - "$host" "$count" <<'PY'
import socket, sys
interface, count = sys.argv[1], int(sys.argv[2])
frame = bytes.fromhex("ffffffffffff02000000000388b5") + bytes(46)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as channel:
    channel.bind((interface, 0))
    for _ in range(max(1, count // 2)):
        channel.send(frame)
raise SystemExit(130)
PY
        ;;
    stop-daemon)
        stop_daemon
        ;;
    alter-journal)
        test -f "$journal" && test ! -L "$journal" || fail "owned journal is unavailable"
        test ! -e "$saved_journal" && test ! -L "$saved_journal" || fail "saved journal is occupied"
        test ! -e "$changed_journal" && test ! -L "$changed_journal" || fail "changed journal is occupied"
        install -m 0600 "$journal" "$saved_journal"
        python3 - "$journal" "$changed_journal" <<'PY'
import json, sys
source, destination = sys.argv[1:]
with open(source, "r", encoding="utf-8") as channel:
    record = json.load(channel)
record["generation"] = int(record["generation"]) + 1
with open(destination, "x", encoding="utf-8") as channel:
    json.dump(record, channel, separators=(",", ":"))
PY
        chmod 0600 "$changed_journal"
        unlink "$journal"
        mv "$changed_journal" "$journal"
        ;;
    restore-journal)
        test -f "$journal" && test ! -L "$journal" || fail "changed journal is unavailable"
        test -f "$saved_journal" && test ! -L "$saved_journal" || fail "saved journal is unavailable"
        unlink "$journal"
        mv "$saved_journal" "$journal"
        ;;
    cleanup)
        cleanup
        ;;
    cleanup-state)
        cleanup_state
        ;;
    *) fail "unknown isolated acceptance phase" ;;
esac
'@

function Invoke-IsolatedRemotePhase {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $FrameCount,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [switch] $AllowFailure
    )

    $Arguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        'sh', '-s', '--', $Phase, $Names.RunId, $Names.Namespace, $Names.HostVeth,
        $Names.PeerVeth, $Names.RemoteRunRoot, [string]$FrameCount, $Scenario
    )
    Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $RemoteProgram -TimeoutSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Test-IsolatedRemoteState {
    param(
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    (Invoke-IsolatedRemotePhase -Phase 'snapshot' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds).Stdout.Trim()
}

function Assert-IsolatedRemoteStateUnchanged {
    param(
        [Parameter(Mandatory)] [string] $Before,
        [Parameter(Mandatory)] [string] $After
    )

    if ($Before -cne $After) {
        throw 'existing network or eBPF identity snapshot changed during isolated acceptance'
    }
}

function Wait-IsolatedRemoteState {
    param(
        [Parameter(Mandatory)] [string] $Expected,
        [Parameter(Mandatory)] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [ValidateRange(1, 5)] [int] $MaxAttempts = 5,
        [ValidateRange(10, 100)] [int] $DelayMilliseconds = 100
    )

    $Current = ''
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        $Current = Test-IsolatedRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
        if ($Expected -ceq $Current) {
            return
        }
        if ($Attempt -lt $MaxAttempts) {
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }
    Assert-IsolatedRemoteStateUnchanged -Before $Expected -After $Current
}

function Invoke-IsolatedMutation {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $FrameCount,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    Invoke-IsolatedRemotePhase -Phase $Phase -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
}

function Convert-Counters {
    param([Parameter(Mandatory)] [string] $Text)

    $Counters = @{}
    foreach ($Line in $Text -split '\r?\n') {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        if ($Line -notmatch '^([12]) ([0-9]+) ([0-9]+)$') {
            throw 'unexpected isolated counter output'
        }
        $Counters[[int]$Matches[1]] = [pscustomobject]@{
            Packets = [uint64]$Matches[2]
            Bytes = [uint64]$Matches[3]
        }
    }
    if ($Counters.Count -ne 2) {
        throw 'both isolated hook counters are required'
    }
    $Counters
}

function Register-IsolatedCleanup {
    param([Parameter(Mandatory)] [scriptblock] $Action)

    $script:IsolatedCleanupAction = $Action
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($null -ne $script:IsolatedCleanupAction) { & $script:IsolatedCleanupAction }
    }
}

$Target = [Environment]::GetEnvironmentVariable('L2_LOOP_TEST_TARGET')
$KeyPath = [Environment]::GetEnvironmentVariable('L2_LOOP_TEST_KEY')
if ([string]::IsNullOrWhiteSpace($Target) -or [string]::IsNullOrWhiteSpace($KeyPath)) {
    throw 'L2_LOOP_TEST_TARGET and L2_LOOP_TEST_KEY are mandatory task-scoped inputs'
}
$KeyItem = Get-Item -LiteralPath $KeyPath
Assert-NoSymlink -Item $KeyItem

$ArtifactRoot = Get-ExactGreenBundle -Commit $Commit
$RunId = [Guid]::NewGuid().ToString('N')
$Names = New-IsolatedNames -RunId $RunId
Assert-GeneratedTarget -Names $Names

$CleanupComplete = $false
$CleanupAction = {
    if (-not $CleanupComplete) {
        $Result = Invoke-IsolatedRemotePhase -Phase 'cleanup' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds -AllowFailure
        if ($Result.ExitCode -ne 0) {
            throw "exact isolated cleanup failed and requires manual review: $($Result.Stderr.Trim())"
        }
        $CleanupComplete = $true
    }
}
$ExitEvent = Register-IsolatedCleanup -Action $CleanupAction
$CancelHandler = [ConsoleCancelEventHandler]{
    param($Sender, $EventArgs)
    $EventArgs.Cancel = $true
    if ($null -ne $script:IsolatedCleanupAction) { & $script:IsolatedCleanupAction }
}
[Console]::add_CancelKeyPress($CancelHandler)

try {
    $null = Invoke-IsolatedRemotePhase -Phase 'precheck' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-IsolatedMutation -Phase 'stage' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $Sources = $ExpectedBundleFiles | ForEach-Object { Join-Path $ArtifactRoot $_ }
    $ScpArguments = Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources $Sources -Destination "$($Names.RemoteRunRoot)/"
    $null = Invoke-ExactProcess -FilePath 'scp' -ArgumentList $ScpArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-IsolatedMutation -Phase 'install' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $BeforeState = Test-IsolatedRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds

    $null = Invoke-IsolatedMutation -Phase 'prepare' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-IsolatedMutation -Phase 'launch' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds

    $PreflightArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        "$($Names.RemoteRunRoot)/l2-loopctl", 'preflight', '--interface', $Names.HostVeth, '--json'
    )
    $Preflight = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $PreflightArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
    $Report = $Preflight.Stdout | ConvertFrom-Json
    if ($Report.decision -cnotin @('ready', 'ready_with_warnings') -or
        $Report.interface.kind -cne 'veth' -or
        -not $Report.interface.isolated -or
        $Report.interface.live_shared) {
        throw 'daemon preflight did not approve the exact isolated veth'
    }

    $PreparedState = Test-IsolatedRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds

    $BlockedArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-attach', '--interface', 'lo', '--run-id', $RunId
    )
    $Blocked = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $BlockedArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds -AllowFailure
    if ($Blocked.ExitCode -ne 4 -or -not $Blocked.Stderr.Contains('PF_LIVE_INTERFACE')) {
        throw 'non-veth isolated attachment was not blocked before BPF work'
    }

    $AttachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-attach', '--interface', $Names.HostVeth, '--run-id', $RunId
    )
    $FaultCode = switch ($Scenario) {
        'TcAttachFailure' { 'TC_ATTACH_FAILED' }
        'MapInitializeFailure' { 'MAP_INITIALIZE_FAILED' }
        default { $null }
    }
    $Attach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $AttachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds -AllowFailure:($null -ne $FaultCode)

    if ($null -ne $FaultCode) {
        if ($Attach.ExitCode -eq 0 -or -not $Attach.Stderr.Contains($FaultCode)) {
            throw "isolated attach did not fail at the expected bounded stage: $FaultCode"
        }
        Wait-IsolatedRemoteState -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
        $null = Invoke-IsolatedMutation -Phase 'cleanup-state' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        Wait-IsolatedRemoteState -Expected $BeforeState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
        & $CleanupAction
        Write-Host "isolated acceptance scenario $Scenario passed for commit $Commit"
        return
    }

    if ($Attach.Stdout.Trim() -cne 'accepted') { throw 'isolated attach was not acknowledged' }
    $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds

    $Detached = $false
    switch ($Scenario) {
        'Success' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $BeforeCounters = Convert-Counters -Text (Invoke-IsolatedRemotePhase -Phase 'counters' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds).Stdout
            $null = Invoke-IsolatedMutation -Phase 'traffic' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $AfterCounters = Convert-Counters -Text (Invoke-IsolatedRemotePhase -Phase 'counters' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds).Stdout
            foreach ($Role in @(1, 2)) {
                if ($AfterCounters[$Role].Packets -lt ($BeforeCounters[$Role].Packets + $FrameCount) -or
                    $AfterCounters[$Role].Bytes -le $BeforeCounters[$Role].Bytes) {
                    throw "isolated hook role $Role did not count the bounded test traffic"
                }
            }
        }
        'DaemonTermination' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'stop-daemon' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'links-down' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            Wait-IsolatedRemoteState -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'traffic' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $Detached = $true
        }
        'IdentityChange' {
            $null = Invoke-IsolatedMutation -Phase 'alter-journal' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $DetachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
                "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-detach', '--run-id', $RunId
            )
            $Mismatch = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $DetachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds -AllowFailure
            if ($Mismatch.ExitCode -ne 4 -or -not $Mismatch.Stderr.Contains('PF_OWNERSHIP_MISMATCH')) {
                throw 'identity-changed detach did not require manual review'
            }
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks-saved' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'restore-journal' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        }
        'TrafficInterruption' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $Interrupted = Invoke-IsolatedRemotePhase -Phase 'traffic-interrupt' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds -AllowFailure
            if ($Interrupted.ExitCode -eq 0) {
                throw 'bounded traffic sender was not interrupted'
            }
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        }
    }

    if (-not $Detached) {
        $DetachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
            "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-detach', '--run-id', $RunId
        )
        $Detach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $DetachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
        if ($Detach.Stdout.Trim() -cne 'accepted') { throw 'isolated detach was not acknowledged' }
    }

    $null = Invoke-IsolatedMutation -Phase 'cleanup-state' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    Wait-IsolatedRemoteState -Expected $BeforeState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    & $CleanupAction
    Write-Host "isolated acceptance scenario $Scenario passed for commit $Commit"
}
finally {
    try { & $CleanupAction } finally {
        [Console]::remove_CancelKeyPress($CancelHandler)
        if ($null -ne $ExitEvent) {
            Unregister-Event -SubscriptionId $ExitEvent.Id -ErrorAction SilentlyContinue
            Remove-Job -Id $ExitEvent.Id -Force -ErrorAction SilentlyContinue
        }
        $script:IsolatedCleanupAction = $null
    }
}
