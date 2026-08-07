[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [ValidateRange(1, 256)]
    [int] $FrameCount = 32,

    [ValidateRange(30, 600)]
    [int] $TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib/IsolatedNames.psm1') -Force

$ExpectedBundleFiles = @(
    'l2-loopd',
    'l2-loopctl',
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
        $Process.StandardInput.Write($StandardInput)
        $Process.StandardInput.Close()
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
        Where-Object { $_.headSha -ceq $Commit -and $_.conclusion -ceq 'success' } |
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
    if ($ChecksumLines.Count -ne 4) {
        throw 'bundle checksum file must contain exactly four entries'
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
journal="/run/l2-loop/tests/$run.json"
pins="/sys/fs/bpf/l2-loop/test/$run"

fail() { printf '%s\n' "$1" >&2; exit 1; }
assert_no_symlink() { test ! -L "$1" || fail "owned path is a symbolic link"; }
assert_generated() {
    test "$(printf '%.12s' "$run")" = "${ns#l2ns-}" || fail "namespace is not generated"
    test "$(printf '%.10s' "$run")" = "${host#l2h}" || fail "host veth is not generated"
    test "$(printf '%.10s' "$run")" = "${peer#l2n}" || fail "peer veth is not generated"
    test "$root" = "/run/l2-loop/accept/$run" || fail "run root is not generated"
}
assert_generated

snapshot() {
    {
        bpftool -j prog show
        bpftool -j map show
        bpftool -j link show
        bpftool -j net
        ip -j link show
        ip -j route show table all
        tc -j qdisc show
        for devpath in /sys/class/net/*; do
            dev=${devpath##*/}
            tc -j filter show dev "$dev" ingress
            tc -j filter show dev "$dev" egress
        done
    } | sha256sum | awk '{print $1}'
}

cleanup_file() {
    path=$1
    if test -e "$path" || test -L "$path"; then
        assert_no_symlink "$path"
        unlink "$path"
    fi
}

cleanup() {
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
            kill -0 "$pid" 2>/dev/null && fail "owned daemon did not stop"
        fi
    fi

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
    if test -d "$pins"; then
        assert_no_symlink "$pins"
        rmdir "$pins"
    fi
    cleanup_file "$journal"
    cleanup_file "$root/counters.json"
    cleanup_file "$root/daemon.pid"
    cleanup_file "$root/daemon.log"
    cleanup_file "$root/l2-loopd"
    cleanup_file "$root/l2-loopctl"
    cleanup_file "$root/l2-loop-ebpf.o"
    cleanup_file "$root/manifest.json"
    cleanup_file "$root/SHA256SUMS"
    if test -d "$root"; then
        assert_no_symlink "$root"
        rmdir "$root"
    fi
}

case "$phase" in
    precheck)
        for command_name in ip tc bpftool python3 sha256sum awk grep; do
            command -v "$command_name" >/dev/null || fail "required acceptance command is unavailable"
        done
        test ! -e "$root" && test ! -L "$root" || fail "run root already exists"
        test ! -e "$journal" && test ! -L "$journal" || fail "run journal already exists"
        test ! -e "$pins" && test ! -L "$pins" || fail "run pin root already exists"
        ! ip link show dev "$host" >/dev/null 2>&1 || fail "generated host veth already exists"
        ! ip netns list | awk '{print $1}' | grep -Fqx -- "$ns" || fail "generated namespace already exists"
        test ! -e /run/l2-loop/agent.sock && test ! -L /run/l2-loop/agent.sock || fail "daemon socket is already occupied"
        ;;
    snapshot)
        snapshot
        ;;
    prepare)
        install -d -m 0700 /run/l2-loop
        install -d -m 0700 /run/l2-loop/accept
        install -d -m 0700 "$root"
        ip netns add "$ns"
        ip link add name "$host" type veth peer name "$peer"
        ip link set dev "$peer" netns "$ns"
        ;;
    install)
        assert_no_symlink "$root"
        cd "$root"
        sha256sum --check SHA256SUMS >/dev/null
        chmod 0755 l2-loopd l2-loopctl
        ;;
    launch)
        cd "$root"
        ./l2-loopd >daemon.log 2>&1 &
        printf '%s\n' "$!" >daemon.pid
        tries=0
        while test ! -S /run/l2-loop/agent.sock && test "$tries" -lt 50; do
            sleep 0.1
            tries=$((tries + 1))
        done
        test -S /run/l2-loop/agent.sock || fail "daemon socket was not created"
        ;;
    verify-hooks)
        python3 - "$journal" "$host" <<'PY'
import json, subprocess, sys
journal_path, interface = sys.argv[1:]
with open(journal_path, encoding="utf-8") as handle:
    record = json.load(handle)
xdp_id = int(record["xdp"]["program_id"])
tc_id = int(record["tc"][0]["program_id"])
subprocess.run(["bpftool", "prog", "show", "id", str(xdp_id)], check=True, stdout=subprocess.DEVNULL)
subprocess.run(["bpftool", "prog", "show", "id", str(tc_id)], check=True, stdout=subprocess.DEVNULL)
xdp = subprocess.check_output(["ip", "-details", "link", "show", "dev", interface], text=True)
tc = subprocess.check_output(["tc", "filter", "show", "dev", interface, "egress"], text=True)
if f"prog/xdp id {xdp_id}" not in xdp or f"id {tc_id}" not in tc:
    raise SystemExit("kernel hook identity does not match the ownership journal")
PY
        ;;
    links-up)
        ip link set dev "$host" up
        ip netns exec "$ns" ip link set dev "$peer" up
        ;;
    counters)
        bpftool -j map dump pinned "$pins/HOOK_STATS" >"$root/counters.json"
        python3 - "$root/counters.json" <<'PY'
import json, sys

def raw_bytes(value):
    if isinstance(value, list) and all(isinstance(item, str) and item.startswith("0x") for item in value):
        return bytes(int(item, 16) for item in value)
    return None

def counter(value):
    if isinstance(value, dict) and "packets" in value and "bytes" in value:
        return int(value["packets"]), int(value["bytes"])
    if isinstance(value, dict) and "value" in value:
        return counter(value["value"])
    raw = raw_bytes(value)
    if raw is None or len(raw) < 16:
        raise SystemExit("unsupported HOOK_STATS value format")
    return int.from_bytes(raw[0:8], "little"), int.from_bytes(raw[8:16], "little")

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle)
for entry in entries:
    key = entry["key"]
    if isinstance(key, dict):
        role = int(key["hook_role"])
    else:
        raw_key = raw_bytes(key)
        if raw_key is None or len(raw_key) < 13:
            raise SystemExit("unsupported HOOK_STATS key format")
        role = raw_key[12]
    values = entry.get("values", [entry.get("value")])
    totals = [counter(value) for value in values]
    print(role, sum(item[0] for item in totals), sum(item[1] for item in totals))
PY
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
    cleanup)
        cleanup
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
        $Names.PeerVeth, $Names.RemoteRunRoot, [string]$FrameCount
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
            throw 'exact isolated cleanup failed and requires manual review'
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
    $BeforeState = Test-IsolatedRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds

    $null = Invoke-IsolatedMutation -Phase 'prepare' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $Sources = $ExpectedBundleFiles | ForEach-Object { Join-Path $ArtifactRoot $_ }
    $ScpArguments = Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources $Sources -Destination "$($Names.RemoteRunRoot)/"
    $null = Invoke-ExactProcess -FilePath 'scp' -ArgumentList $ScpArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-IsolatedMutation -Phase 'install' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
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

    $AttachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-attach', '--interface', $Names.HostVeth, '--run-id', $RunId
    )
    $Attach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $AttachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
    if ($Attach.Stdout.Trim() -cne 'accepted') { throw 'isolated attach was not acknowledged' }
    $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds

    $BeforeCounters = Convert-Counters -Text (Invoke-IsolatedRemotePhase -Phase 'counters' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds).Stdout
    $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-IsolatedMutation -Phase 'traffic' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
    $AfterCounters = Convert-Counters -Text (Invoke-IsolatedRemotePhase -Phase 'counters' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds).Stdout
    foreach ($Role in @(1, 2)) {
        if ($AfterCounters[$Role].Packets -lt ($BeforeCounters[$Role].Packets + $FrameCount) -or
            $AfterCounters[$Role].Bytes -le $BeforeCounters[$Role].Bytes) {
            throw "isolated hook role $Role did not count the bounded test traffic"
        }
    }

    $DetachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-detach', '--run-id', $RunId
    )
    $Detach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $DetachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
    if ($Detach.Stdout.Trim() -cne 'accepted') { throw 'isolated detach was not acknowledged' }

    & $CleanupAction
    $AfterState = Test-IsolatedRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    Assert-IsolatedRemoteStateUnchanged -Before $BeforeState -After $AfterState
    Write-Host "isolated acceptance passed for commit $Commit"
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
