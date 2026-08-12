[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [ValidateRange(1, 256)]
    [int] $FrameCount = 32,

    [ValidateRange(30, 600)]
    [int] $TimeoutSeconds = 180,

    [ValidateSet('Success', 'TcAttachFailure', 'MapInitializeFailure', 'DaemonTermination', 'IdentityChange', 'TrafficInterruption', 'PassiveObservation', 'ObservationMapFailure', 'ObservationIdentityChange', 'RateWindows', 'RateSamplingFailure', 'RateGenerationReset')]
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
second_run=$9
RATE_SAMPLE_ITERATIONS=65
RATE_FRAMES_PER_DIRECTION=9
journal="/run/l2-loop/tests/$run.json"
pins="/sys/fs/bpf/l2-loop/test/$run"
second_journal="/run/l2-loop/tests/$second_run.json"
second_pins="/sys/fs/bpf/l2-loop/test/$second_run"
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
case "$second_run" in *[!0-9a-f]*|'') fail "second run ID is not generated" ;; esac
test "${#second_run}" -eq 32 || fail "second run ID length is invalid"
test "$second_run" != "$run" || fail "second run ID did not change"
case "$scenario" in
    Success|TcAttachFailure|MapInitializeFailure|DaemonTermination|IdentityChange|TrafficInterruption|PassiveObservation|ObservationMapFailure|ObservationIdentityChange|RateWindows|RateSamplingFailure|RateGenerationReset) ;;
    *) fail "unknown isolated acceptance scenario" ;;
esac

snapshot() {
    printf 'ebpf_identity='
    "$root/l2-loop-hostcheck" snapshot | sha256sum | awk '{print $1}'
    printf 'network_links='
    ip -j link show | sha256sum | awk '{print $1}'
    printf 'network_routes='
    ip -j route show table all | sha256sum | awk '{print $1}'
}

snapshot_prepared() {
    printf 'ebpf_identity='
    "$root/l2-loop-hostcheck" snapshot | sha256sum | awk '{print $1}'
    printf 'network_links='
    ip -j link show | python3 -c 'import json,sys; excluded=sys.argv[1]; value=json.load(sys.stdin); sum(1 for item in value if item.get("ifname") == excluded) != 1 and sys.exit("generated host veth is not unique"); filtered=[item for item in value if item.get("ifname") != excluded]; print(json.dumps(filtered,sort_keys=True,separators=(",",":")))' "$host" | sha256sum | awk '{print $1}'
    printf 'network_routes='
    ip -j route show table all | sha256sum | awk '{print $1}'
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
        cleanup_file "$second_pins/$name"
    done
    cleanup_dir "$pins"
    cleanup_dir "$second_pins"
    cleanup_file "$journal"
    cleanup_file "$second_journal"
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
        test ! -e "$second_journal" && test ! -L "$second_journal" || fail "second run journal already exists"
        test ! -e "$saved_journal" && test ! -L "$saved_journal" || fail "saved journal already exists"
        test ! -e "$changed_journal" && test ! -L "$changed_journal" || fail "changed journal already exists"
        test ! -e "$pins" && test ! -L "$pins" || fail "run pin root already exists"
        test ! -e "$second_pins" && test ! -L "$second_pins" || fail "second run pin root already exists"
        ! ip link show dev "$host" >/dev/null 2>&1 || fail "generated host veth already exists"
        ! ip netns list | awk '{print $1}' | grep -Fqx -- "$ns" || fail "generated namespace already exists"
        test ! -e /run/l2-loop/agent.sock && test ! -L /run/l2-loop/agent.sock || fail "daemon socket is already occupied"
        ;;
    snapshot)
        snapshot
        ;;
    snapshot-prepared)
        snapshot_prepared
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
        ip link set dev "$host" addrgenmode none
        ip netns exec "$ns" ip link set dev "$peer" addrgenmode none
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
            ObservationMapFailure)
                env L2_LOOP_ACCEPTANCE_FAULT=observation-map-read ./l2-loopd >daemon.log 2>&1 &
                ;;
            RateSamplingFailure)
                env L2_LOOP_ACCEPTANCE_FAULT=rate-sampling-map-read ./l2-loopd >daemon.log 2>&1 &
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
    verify-second-hooks)
        "$root/l2-loop-hostcheck" 'verify-owned' --journal "$second_journal" --interface "$host"
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
    vlan-probe)
        python3 - "$host" "$ns" "$peer" <<'PY'
import socket, struct, subprocess, sys, time

host, namespace, peer = sys.argv[1:]
source = bytes.fromhex("020000000001")
frame = bytes.fromhex("333300000001") + source + bytes.fromhex("8100007b86dd") + bytes(42)
if len(frame) != 60:
    raise SystemExit("invalid VLAN probe length")

SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6

def recv_wire(channel):
    frame, ancillary, _, _ = channel.recvmsg(65535, 1024)
    for level, kind, value in ancillary:
        if level == SOL_PACKET and kind == PACKET_AUXDATA and len(value) >= 20:
            status, _, _, _, _, vlan_tci, vlan_tpid = struct.unpack("=IIIHHHH", value[:20])
            if status & TP_STATUS_VLAN_VALID:
                tpid = vlan_tpid if status & TP_STATUS_VLAN_TPID_VALID else 0x8100
                return (
                    frame[:12]
                    + tpid.to_bytes(2, "big")
                    + vlan_tci.to_bytes(2, "big")
                    + frame[12:]
                )
    return frame

sender = """
import socket, sys
interface, frame_hex = sys.argv[1:]
frame = bytes.fromhex(frame_hex)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as channel:
    channel.bind((interface, 0))
    channel.send(frame)
"""
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as receiver:
    receiver.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    receiver.bind((host, 0))
    receiver.settimeout(5.0)
    subprocess.run(
        ["ip", "netns", "exec", namespace, "python3", "-c", sender, peer, frame.hex()],
        check=True,
        timeout=8,
    )
    deadline = time.monotonic() + 5.0
    while True:
        receiver.settimeout(max(0.01, deadline - time.monotonic()))
        if recv_wire(receiver) == frame:
            break
PY
        ;;
    traffic-matrix)
        python3 - "$host" "$ns" "$peer" "$count" <<'PY'
import json, select, socket, struct, subprocess, sys, time

host, namespace, peer, raw_count = sys.argv[1:]
frame_count = int(raw_count)
source = bytes.fromhex("020000000001")
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6

def recv_wire(channel):
    frame, ancillary, _, _ = channel.recvmsg(65535, 1024)
    for level, kind, value in ancillary:
        if level == SOL_PACKET and kind == PACKET_AUXDATA and len(value) >= 20:
            status, _, _, _, _, vlan_tci, vlan_tpid = struct.unpack("=IIIHHHH", value[:20])
            if status & TP_STATUS_VLAN_VALID:
                tpid = vlan_tpid if status & TP_STATUS_VLAN_TPID_VALID else 0x8100
                return (
                    frame[:12]
                    + tpid.to_bytes(2, "big")
                    + vlan_tci.to_bytes(2, "big")
                    + frame[12:]
                )
    return frame

def untagged(destination, ether_type):
    return bytes.fromhex(destination) + source + bytes.fromhex(ether_type) + bytes(46)

def tagged(destination, tpid, tci, inner_type):
    return (
        bytes.fromhex(destination)
        + source
        + bytes.fromhex(tpid)
        + bytes.fromhex(tci)
        + bytes.fromhex(inner_type)
        + bytes(42)
    )

frames = {
    'l2-broadcast': untagged("ffffffffffff", "0806"),
    'ipv4-multicast': untagged("01005e000001", "0800"),
    'ipv6-multicast': untagged("333300000001", "86dd"),
    'other-l2-multicast': untagged("01005f000001", "88b5"),
    'link-local-control': untagged("0180c200000e", "88cc"),
    'unicast-or-unclassified': untagged("020000000002", "0800"),
    '8021q': tagged("333300000001", "8100", "007b", "86dd"),
    '8021ad': tagged("01005e000001", "88a8", "0007", "0800"),
    'nested-vlan': bytes.fromhex("01005f000001")
        + source
        + bytes.fromhex("88a80007810000080800")
        + bytes(38),
}
if len(frames) != 9 or any(len(frame) != 60 for frame in frames.values()):
    raise SystemExit("invalid classified traffic matrix")

def receive_exact(channel, expected, timeout_seconds):
    remaining = {frame: frame_count for frame in expected.values()}
    deadline = time.monotonic() + timeout_seconds
    while any(remaining.values()):
        channel.settimeout(max(0.01, deadline - time.monotonic()))
        frame = recv_wire(channel)
        if frame in remaining and remaining[frame] > 0:
            remaining[frame] -= 1
    if any(remaining.values()):
        raise SystemExit("classified traffic receiver count mismatch")

sender = """
import json, socket, sys
interface, raw_frames, raw_count = sys.argv[1:]
frames = [bytes.fromhex(value) for value in json.loads(raw_frames)]
count = int(raw_count)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as channel:
    channel.bind((interface, 0))
    for frame in frames:
        for _ in range(count):
            channel.send(frame)
"""
frame_json = json.dumps([frame.hex() for frame in frames.values()], separators=(",", ":"))
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as receiver:
    receiver.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    receiver.bind((host, 0))
    subprocess.run(
        [
            "ip", "netns", "exec", namespace, "python3", "-c", sender,
            peer, frame_json, str(frame_count),
        ],
        check=True,
        timeout=15,
    )
    receive_exact(receiver, frames, 10.0)

receiver = """
import json, socket, struct, sys, time
interface, raw_frames, raw_count = sys.argv[1:]
frames = {bytes.fromhex(value): int(raw_count) for value in json.loads(raw_frames)}
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6

def recv_wire(channel):
    frame, ancillary, _, _ = channel.recvmsg(65535, 1024)
    for level, kind, value in ancillary:
        if level == SOL_PACKET and kind == PACKET_AUXDATA and len(value) >= 20:
            status, _, _, _, _, vlan_tci, vlan_tpid = struct.unpack("=IIIHHHH", value[:20])
            if status & TP_STATUS_VLAN_VALID:
                tpid = vlan_tpid if status & TP_STATUS_VLAN_TPID_VALID else 0x8100
                return (
                    frame[:12]
                    + tpid.to_bytes(2, "big")
                    + vlan_tci.to_bytes(2, "big")
                    + frame[12:]
                )
    return frame

with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as receiver:
    receiver.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    receiver.bind((interface, 0))
    print("ready", flush=True)
    deadline = time.monotonic() + 10.0
    while any(frames.values()):
        receiver.settimeout(max(0.01, deadline - time.monotonic()))
        frame = recv_wire(receiver)
        if frame in frames and frames[frame] > 0:
            frames[frame] -= 1
    if any(frames.values()):
        raise SystemExit("classified traffic receiver count mismatch")
"""
child = subprocess.Popen(
    [
        "ip", "netns", "exec", namespace, "python3", "-c", receiver,
        peer, frame_json, str(frame_count),
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    universal_newlines=True,
)
try:
    ready, _, _ = select.select([child.stdout], [], [], 5.0)
    if not ready or child.stdout.readline().strip() != "ready":
        raise RuntimeError("classified peer receiver was not ready")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as host_sender:
        host_sender.bind((host, 0))
        for frame in frames.values():
            for _ in range(frame_count):
                host_sender.send(frame)
    child.communicate(timeout=12)
    if child.returncode != 0:
        raise RuntimeError("classified peer receiver failed")
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
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
        $Names.PeerVeth, $Names.RemoteRunRoot, [string]$FrameCount, $Scenario, $SecondRunId
    )
    Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $RemoteProgram -TimeoutSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Test-IsolatedRemoteState {
    param(
        [ValidateSet('snapshot', 'snapshot-prepared')] [string] $Phase = 'snapshot',
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    (Invoke-IsolatedRemotePhase -Phase $Phase -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds).Stdout.Trim()
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
        [ValidateSet('snapshot', 'snapshot-prepared')] [string] $Phase = 'snapshot',
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
        $Current = Test-IsolatedRemoteState -Phase $Phase -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
        if ($Expected -ceq $Current) {
            return
        }
        if ($Attempt -lt $MaxAttempts) {
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }
    if ($Phase -cin @('snapshot', 'snapshot-prepared')) {
        $ExpectedComponents = @($Expected -split "`r?`n")
        $CurrentComponents = @($Current -split "`r?`n")
        $ChangedComponents = for ($Index = 0; $Index -lt [Math]::Max($ExpectedComponents.Count, $CurrentComponents.Count); $Index++) {
            if ($Index -ge $ExpectedComponents.Count -or $Index -ge $CurrentComponents.Count -or $ExpectedComponents[$Index] -cne $CurrentComponents[$Index]) {
                if ($Index -lt $ExpectedComponents.Count) { ($ExpectedComponents[$Index] -split '=', 2)[0] }
                elseif ($Index -lt $CurrentComponents.Count) { ($CurrentComponents[$Index] -split '=', 2)[0] }
            }
        }
        throw "existing network or eBPF identity snapshot changed during isolated acceptance: $(@($ChangedComponents) -join ', ')"
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

function Invoke-ObservationCli {
    param(
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [string] $Interface,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [switch] $Json,
        [switch] $AllowFailure
    )

    $RemoteCommand = @('l2-loopctl', 'observe', '--interface', $Interface)
    $RemoteCommand[0] = "$($Names.RemoteRunRoot)/l2-loopctl"
    if ($Json) { $RemoteCommand += '--json' }
    $Arguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments $RemoteCommand
    Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Invoke-StatusCli {
    param(
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [AllowNull()] [string] $Interface,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [switch] $Json,
        [switch] $AllowFailure
    )

    $RemoteCommand = @('l2-loopctl', 'status')
    $RemoteCommand[0] = "$($Names.RemoteRunRoot)/l2-loopctl"
    if (-not [string]::IsNullOrWhiteSpace($Interface)) {
        $RemoteCommand += @('--interface', $Interface)
    }
    if ($Json) { $RemoteCommand += '--json' }
    $Arguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments $RemoteCommand
    Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Assert-ObservationFailure {
    param(
        [Parameter(Mandatory)] [psobject] $Result,
        [Parameter(Mandatory)] [string] $Code
    )

    if ($Result.ExitCode -ne 1 -or -not $Result.Stderr.Contains($Code)) {
        throw "observation request did not fail with $Code"
    }
}

function Convert-ObservationJson {
    param([Parameter(Mandatory)] [psobject] $Result)

    if ([string]::IsNullOrWhiteSpace($Result.Stdout) -or -not [string]::IsNullOrWhiteSpace($Result.Stderr)) {
        throw 'observation JSON response streams are invalid'
    }
    $Result.Stdout | ConvertFrom-Json
}

function Get-ObservationHook {
    param(
        [Parameter(Mandatory)] [psobject] $Snapshot,
        [Parameter(Mandatory)] [string] $Role
    )

    $Matches = @($Snapshot.hooks | Where-Object { $_.role -ceq $Role })
    if ($Matches.Count -ne 1) { throw "observation hook $Role is not unique" }
    $Matches[0]
}

function Get-ObservationClass {
    param(
        [Parameter(Mandatory)] [psobject] $Hook,
        [Parameter(Mandatory)] [string] $Class
    )

    $Matches = @($Hook.classes | Where-Object { $_.traffic_class -ceq $Class })
    if ($Matches.Count -ne 1) { throw "observation class $Class is not unique" }
    $Matches[0].counters
}

function Get-CheckedCounterDelta {
    param(
        [Parameter(Mandatory)] [object] $Before,
        [Parameter(Mandatory)] [object] $After,
        [Parameter(Mandatory)] [string] $Evidence
    )

    $BeforeValue = [uint64]$Before
    $AfterValue = [uint64]$After
    if ($AfterValue -lt $BeforeValue) { throw "counter decreased: $Evidence" }
    [uint64]($AfterValue - $BeforeValue)
}

function Assert-ObservationIdentity {
    param(
        [Parameter(Mandatory)] [psobject] $Snapshot,
        [Parameter(Mandatory)] [psobject] $Names,
        [ValidateSet('healthy', 'degraded')] [string] $ExpectedHealth = 'healthy'
    )

    if ($Snapshot.schema_version -ne 2 -or
        $Snapshot.interface -cne $Names.HostVeth -or
        [uint64]$Snapshot.generation -eq 0 -or
        [uint64]$Snapshot.captured_at_unix_ms -eq 0 -or
        $Snapshot.health -cne $ExpectedHealth -or
        @($Snapshot.hooks).Count -ne 2) {
        throw 'observation snapshot identity is invalid'
    }
    $null = Get-ObservationHook -Snapshot $Snapshot -Role 'external_xdp_ingress'
    $null = Get-ObservationHook -Snapshot $Snapshot -Role 'physical_tc_egress'
}

function Assert-CountersMonotonic {
    param(
        [Parameter(Mandatory)] [psobject] $Before,
        [Parameter(Mandatory)] [psobject] $After,
        [Parameter(Mandatory)] [string] $Evidence
    )

    $null = Get-CheckedCounterDelta -Before $Before.packets -After $After.packets -Evidence "$Evidence packets"
    $null = Get-CheckedCounterDelta -Before $Before.bytes -After $After.bytes -Evidence "$Evidence bytes"
}

function Assert-CumulativeObservationMonotonic {
    param(
        [Parameter(Mandatory)] [psobject] $Before,
        [Parameter(Mandatory)] [psobject] $After
    )

    foreach ($Role in @('external_xdp_ingress', 'physical_tc_egress')) {
        $BeforeHook = Get-ObservationHook -Snapshot $Before -Role $Role
        $AfterHook = Get-ObservationHook -Snapshot $After -Role $Role
        Assert-CountersMonotonic -Before $BeforeHook.total -After $AfterHook.total -Evidence "$Role total"
        foreach ($Class in @('l2_broadcast', 'ipv4_multicast', 'ipv6_multicast', 'other_l2_multicast', 'link_local_control', 'unicast_or_unclassified')) {
            Assert-CountersMonotonic -Before (Get-ObservationClass -Hook $BeforeHook -Class $Class) -After (Get-ObservationClass -Hook $AfterHook -Class $Class) -Evidence "$Role $Class"
        }
        Assert-CountersMonotonic -Before $BeforeHook.parse_errors -After $AfterHook.parse_errors -Evidence "$Role parse errors"
    }
}

function Assert-RateCounterEvidence {
    param(
        [Parameter(Mandatory)] [psobject] $Counters,
        [Parameter(Mandatory)] [uint64] $ElapsedNs,
        [Parameter(Mandatory)] [string] $Evidence,
        [switch] $RequireTraffic,
        [switch] $RequireNonZeroRate
    )

    if ($ElapsedNs -eq 0) { throw "zero elapsed time for $Evidence" }
    $ExpectedPacketsPerSecond = [uint64][decimal]::Truncate(
        ([decimal][uint64]$Counters.packet_delta * [decimal]1000000000) / [decimal]$ElapsedNs
    )
    $ExpectedBytesPerSecond = [uint64][decimal]::Truncate(
        ([decimal][uint64]$Counters.byte_delta * [decimal]1000000000) / [decimal]$ElapsedNs
    )
    if ([uint64]$Counters.packets_per_second -ne $ExpectedPacketsPerSecond -or
        [uint64]$Counters.bytes_per_second -ne $ExpectedBytesPerSecond) {
        throw "rate arithmetic is not externally recomputable for $Evidence"
    }
    if ($RequireTraffic -and
        ([uint64]$Counters.packet_delta -eq 0 -or [uint64]$Counters.byte_delta -eq 0)) {
        throw "expected bounded traffic is absent from $Evidence`: packet_delta $($Counters.packet_delta), byte_delta $($Counters.byte_delta), elapsed_ns $ElapsedNs"
    }
    if ($RequireNonZeroRate -and
        ([uint64]$Counters.packets_per_second -eq 0 -or [uint64]$Counters.bytes_per_second -eq 0)) {
        throw "expected bounded traffic rate is absent from $Evidence"
    }
}

function Assert-DetailedRateWindows {
    param(
        [Parameter(Mandatory)] [psobject] $Snapshot,
        [Parameter(Mandatory)] [string[]] $ExpectedStates,
        [switch] $RequireTraffic
    )

    $ExpectedWindowMs = @(1000, 10000, 60000)
    $ExpectedRoles = @('external_xdp_ingress', 'physical_tc_egress')
    $ExpectedClasses = @('l2_broadcast', 'ipv4_multicast', 'ipv6_multicast', 'other_l2_multicast', 'link_local_control', 'unicast_or_unclassified')
    $Windows = @($Snapshot.rate_windows)
    if ($Windows.Count -ne 3 -or $ExpectedStates.Count -ne 3) {
        throw 'detailed rate window count changed'
    }
    for ($Index = 0; $Index -lt 3; $Index++) {
        $Window = $Windows[$Index]
        if ([uint64]$Window.window_ms -ne [uint64]$ExpectedWindowMs[$Index] -or $Window.state -cne $ExpectedStates[$Index]) {
            throw "unexpected detailed rate window state at index $Index`: expected $($ExpectedStates[$Index]), actual $($Window.state), coverage $($Window.coverage_ms) ms"
        }
        if ($Window.state -cne 'ready') {
            if ($null -ne $Window.elapsed_ns -or $null -ne $Window.start_unix_ms -or
                $null -ne $Window.end_unix_ms -or $null -ne $Window.hooks) {
                throw "non-ready detailed window exposed rate evidence at index $Index"
            }
            continue
        }
        $ElapsedNs = [uint64]$Window.elapsed_ns
        if ($ElapsedNs -lt ([uint64]$Window.window_ms * [uint64]1000000) -or
            [uint64]$Window.start_unix_ms -eq 0 -or [uint64]$Window.end_unix_ms -lt [uint64]$Window.start_unix_ms) {
            throw "ready detailed window has invalid endpoints at index $Index"
        }
        $Hooks = @($Window.hooks)
        if ($Hooks.Count -ne 2) { throw 'ready detailed window hook count changed' }
        for ($HookIndex = 0; $HookIndex -lt 2; $HookIndex++) {
            $Hook = $Hooks[$HookIndex]
            if ($Hook.role -cne $ExpectedRoles[$HookIndex]) { throw 'ready detailed window hook order changed' }
            Assert-RateCounterEvidence -Counters $Hook.total -ElapsedNs $ElapsedNs -Evidence "$($Hook.role) total" -RequireTraffic:$RequireTraffic -RequireNonZeroRate:$RequireTraffic
            $Classes = @($Hook.classes)
            if ($Classes.Count -ne 6) { throw 'ready detailed window class count changed' }
            for ($ClassIndex = 0; $ClassIndex -lt 6; $ClassIndex++) {
                if ($Classes[$ClassIndex].traffic_class -cne $ExpectedClasses[$ClassIndex]) { throw 'ready detailed window class order changed' }
                Assert-RateCounterEvidence -Counters $Classes[$ClassIndex].counters -ElapsedNs $ElapsedNs -Evidence "$($Hook.role) $($Classes[$ClassIndex].traffic_class)" -RequireTraffic:$RequireTraffic
            }
            Assert-RateCounterEvidence -Counters $Hook.parse_errors -ElapsedNs $ElapsedNs -Evidence "$($Hook.role) parse errors"
        }
    }
}

function Get-OnlyStatusInterface {
    param([Parameter(Mandatory)] [psobject] $Status)

    $Interfaces = @($Status.interfaces)
    if ($Interfaces.Count -ne 1) { throw 'status did not return exactly one active interface' }
    $Interfaces[0]
}

function Assert-StatusRateWindows {
    param(
        [Parameter(Mandatory)] [psobject] $Status,
        [Parameter(Mandatory)] [string[]] $ExpectedStates,
        [switch] $RequireTraffic
    )

    $Interface = Get-OnlyStatusInterface -Status $Status
    $ExpectedWindowMs = @(1000, 10000, 60000)
    $Windows = @($Interface.rate_windows)
    if ($Windows.Count -ne 3 -or $ExpectedStates.Count -ne 3) { throw 'status rate window count changed' }
    for ($Index = 0; $Index -lt 3; $Index++) {
        $Window = $Windows[$Index]
        if ([uint64]$Window.window_ms -ne [uint64]$ExpectedWindowMs[$Index] -or $Window.state -cne $ExpectedStates[$Index]) {
            throw "unexpected status rate window state at index $Index"
        }
        if ($Window.state -cne 'ready') {
            if ($null -ne $Window.elapsed_ns -or $null -ne $Window.start_unix_ms -or $null -ne $Window.end_unix_ms -or
                $null -ne $Window.xdp_ingress -or $null -ne $Window.tc_egress) {
                throw "non-ready status window exposed rate evidence at index $Index"
            }
            continue
        }
        $ElapsedNs = [uint64]$Window.elapsed_ns
        if ($ElapsedNs -lt ([uint64]$Window.window_ms * [uint64]1000000)) { throw 'status window endpoint is shorter than its duration' }
        Assert-RateCounterEvidence -Counters $Window.xdp_ingress -ElapsedNs $ElapsedNs -Evidence 'status XDP ingress' -RequireTraffic:$RequireTraffic -RequireNonZeroRate:$RequireTraffic
        Assert-RateCounterEvidence -Counters $Window.tc_egress -ElapsedNs $ElapsedNs -Evidence 'status TC egress' -RequireTraffic:$RequireTraffic -RequireNonZeroRate:$RequireTraffic
    }
}

function Assert-VlanProbeDelta {
    param(
        [Parameter(Mandatory)] [psobject] $Before,
        [Parameter(Mandatory)] [psobject] $After
    )

    if ($Before.vlan_visibility -cne 'unknown' -or $After.vlan_visibility -cne 'verified_visible') {
        throw 'valid single-tag VLAN traffic did not promote visibility'
    }
    $BeforeXdp = Get-ObservationHook -Snapshot $Before -Role 'external_xdp_ingress'
    $AfterXdp = Get-ObservationHook -Snapshot $After -Role 'external_xdp_ingress'
    $BeforeTc = Get-ObservationHook -Snapshot $Before -Role 'physical_tc_egress'
    $AfterTc = Get-ObservationHook -Snapshot $After -Role 'physical_tc_egress'
    if ((Get-CheckedCounterDelta -Before $BeforeXdp.total.packets -After $AfterXdp.total.packets -Evidence 'VLAN XDP total packets') -ne 1 -or
        (Get-CheckedCounterDelta -Before $BeforeXdp.total.bytes -After $AfterXdp.total.bytes -Evidence 'VLAN XDP total bytes') -le 0 -or
        (Get-CheckedCounterDelta -Before (Get-ObservationClass -Hook $BeforeXdp -Class 'ipv6_multicast').packets -After (Get-ObservationClass -Hook $AfterXdp -Class 'ipv6_multicast').packets -Evidence 'VLAN IPv6 packets') -ne 1 -or
        (Get-CheckedCounterDelta -Before $BeforeTc.total.packets -After $AfterTc.total.packets -Evidence 'VLAN TC total packets') -ne 0) {
        throw 'single-tag VLAN probe produced unexpected hook counters'
    }
}

function Assert-PassiveMatrixDelta {
    param(
        [Parameter(Mandatory)] [psobject] $Before,
        [Parameter(Mandatory)] [psobject] $After,
        [Parameter(Mandatory)] [int] $FrameCount
    )

    if ($Before.interface -cne $After.interface -or
        [uint64]$Before.ifindex -ne [uint64]$After.ifindex -or
        [uint64]$Before.generation -ne [uint64]$After.generation) {
        throw 'observation identity changed across the traffic matrix'
    }
    $ExpectedMultipliers = [ordered]@{
        l2_broadcast = 1
        ipv4_multicast = 2
        ipv6_multicast = 2
        other_l2_multicast = 2
        link_local_control = 1
        unicast_or_unclassified = 1
    }
    foreach ($Role in @('external_xdp_ingress', 'physical_tc_egress')) {
        $BeforeHook = Get-ObservationHook -Snapshot $Before -Role $Role
        $AfterHook = Get-ObservationHook -Snapshot $After -Role $Role
        $TotalPackets = Get-CheckedCounterDelta -Before $BeforeHook.total.packets -After $AfterHook.total.packets -Evidence "$Role total packets"
        $TotalBytes = Get-CheckedCounterDelta -Before $BeforeHook.total.bytes -After $AfterHook.total.bytes -Evidence "$Role total bytes"
        if ($TotalPackets -ne [uint64](9 * $FrameCount) -or $TotalBytes -eq 0) {
            throw "classified traffic total mismatch for $Role"
        }
        foreach ($Class in $ExpectedMultipliers.Keys) {
            $BeforeCounters = Get-ObservationClass -Hook $BeforeHook -Class $Class
            $AfterCounters = Get-ObservationClass -Hook $AfterHook -Class $Class
            $Packets = Get-CheckedCounterDelta -Before $BeforeCounters.packets -After $AfterCounters.packets -Evidence "$Role $Class packets"
            $Bytes = Get-CheckedCounterDelta -Before $BeforeCounters.bytes -After $AfterCounters.bytes -Evidence "$Role $Class bytes"
            if ($Packets -ne [uint64]($ExpectedMultipliers[$Class] * $FrameCount) -or $Bytes -eq 0) {
                throw "classified traffic mismatch for $Role $Class"
            }
        }
        if ((Get-CheckedCounterDelta -Before $BeforeHook.parse_errors.packets -After $AfterHook.parse_errors.packets -Evidence "$Role parse error packets") -ne 0 -or
            (Get-CheckedCounterDelta -Before $BeforeHook.parse_errors.bytes -After $AfterHook.parse_errors.bytes -Evidence "$Role parse error bytes") -ne 0) {
            throw "nested VLAN traffic raised a parse error for $Role"
        }
    }
}

function Assert-StatusMatchesObservation {
    param(
        [Parameter(Mandatory)] [psobject] $Status,
        [Parameter(Mandatory)] [psobject] $Snapshot
    )

    $Interfaces = @($Status.interfaces)
    if ($Interfaces.Count -ne 1) { throw 'status did not return exactly one active interface' }
    $Interface = $Interfaces[0]
    $Xdp = Get-ObservationHook -Snapshot $Snapshot -Role 'external_xdp_ingress'
    $Tc = Get-ObservationHook -Snapshot $Snapshot -Role 'physical_tc_egress'
    if ($Interface.interface -cne $Snapshot.interface -or
        [uint64]$Interface.generation -ne [uint64]$Snapshot.generation -or
        $Interface.vlan_visibility -cne $Snapshot.vlan_visibility -or
        [uint64]$Interface.xdp_ingress.packets -ne [uint64]$Xdp.total.packets -or
        [uint64]$Interface.tc_egress.packets -ne [uint64]$Tc.total.packets) {
        throw 'status summary does not match the observation snapshot'
    }
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
$SecondRunId = [Guid]::NewGuid().ToString('N')
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

    $PreparedState = Test-IsolatedRemoteState -Phase 'snapshot-prepared' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds

    if ($Scenario -ceq 'PassiveObservation') {
        $MissingObservation = Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
        Assert-ObservationFailure -Result $MissingObservation -Code 'OBS_SESSION_NOT_FOUND'
        $MissingStatus = Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
        Assert-ObservationFailure -Result $MissingStatus -Code 'OBS_SESSION_NOT_FOUND'
        $EmptyStatus = Convert-ObservationJson -Result (Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $null -TimeoutSeconds $TimeoutSeconds -Json)
        if (@($EmptyStatus.interfaces).Count -ne 0) {
            throw 'status reported an interface before an isolated session was active'
        }
    }

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
        Wait-IsolatedRemoteState -Phase 'snapshot-prepared' -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
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
            Wait-IsolatedRemoteState -Phase 'snapshot-prepared' -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
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
            $null = Invoke-IsolatedMutation -Phase 'restore-journal' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        }
        'TrafficInterruption' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $Interrupted = Invoke-IsolatedRemotePhase -Phase 'traffic-interrupt' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds -AllowFailure
            if ($Interrupted.ExitCode -eq 0) {
                throw 'bounded traffic sender was not interrupted'
            }
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        }
        'PassiveObservation' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds

            $WrongObservation = Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface 'lo' -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
            Assert-ObservationFailure -Result $WrongObservation -Code 'OBS_INTERFACE_MISMATCH'
            $WrongStatus = Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface 'lo' -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
            Assert-ObservationFailure -Result $WrongStatus -Code 'OBS_SESSION_NOT_FOUND'

            $ObservationText = Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds
            $StatusText = Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds
            if ([string]::IsNullOrWhiteSpace($ObservationText.Stdout) -or [string]::IsNullOrWhiteSpace($StatusText.Stdout)) {
                throw 'text observation control path returned an empty response'
            }

            $BeforeProbe = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $BeforeProbe -Names $Names
            $null = Invoke-IsolatedMutation -Phase 'vlan-probe' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds
            $AfterProbe = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $AfterProbe -Names $Names
            Assert-VlanProbeDelta -Before $BeforeProbe -After $AfterProbe

            $BeforeMatrix = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $AfterMatrix = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $AfterMatrix -Names $Names
            Assert-PassiveMatrixDelta -Before $BeforeMatrix -After $AfterMatrix -FrameCount $FrameCount

            $Status = Convert-ObservationJson -Result (Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-StatusMatchesObservation -Status $Status -Snapshot $AfterMatrix
        }
        'RateWindows' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $InitialRateSnapshot = $null
            for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
                $InitialRateSnapshot = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
                if (@($InitialRateSnapshot.rate_windows)[0].state -ceq 'ready') { break }
                Start-Sleep -Seconds 1
            }
            Assert-ObservationIdentity -Snapshot $InitialRateSnapshot -Names $Names
            Assert-DetailedRateWindows -Snapshot $InitialRateSnapshot -ExpectedStates @('ready', 'warming_up', 'warming_up')
            $InitialRateStatus = Convert-ObservationJson -Result (Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-StatusMatchesObservation -Status $InitialRateStatus -Snapshot $InitialRateSnapshot
            Assert-StatusRateWindows -Status $InitialRateStatus -ExpectedStates @('ready', 'warming_up', 'warming_up')

            $PreviousRateSnapshot = $InitialRateSnapshot
            $RateTimer = [System.Diagnostics.Stopwatch]::StartNew()
            for ($RateIteration = 1; $RateIteration -le 65; $RateIteration++) {
                $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds
                if ($RateIteration -in @(3, 12, 63)) {
                    $ExpectedStates = switch ($RateIteration) {
                        3 { @('ready', 'warming_up', 'warming_up') }
                        12 { @('ready', 'ready', 'warming_up') }
                        63 { @('ready', 'ready', 'ready') }
                    }
                    $CurrentRateSnapshot = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
                    Assert-ObservationIdentity -Snapshot $CurrentRateSnapshot -Names $Names
                    Assert-CumulativeObservationMonotonic -Before $PreviousRateSnapshot -After $CurrentRateSnapshot
                    Assert-DetailedRateWindows -Snapshot $CurrentRateSnapshot -ExpectedStates $ExpectedStates -RequireTraffic
                    $CurrentRateStatus = Convert-ObservationJson -Result (Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
                    Assert-StatusMatchesObservation -Status $CurrentRateStatus -Snapshot $CurrentRateSnapshot
                    Assert-StatusRateWindows -Status $CurrentRateStatus -ExpectedStates $ExpectedStates
                    $PreviousRateSnapshot = $CurrentRateSnapshot
                }
                $RemainingMilliseconds = ([int64]$RateIteration * 1000) - $RateTimer.ElapsedMilliseconds
                if ($RemainingMilliseconds -gt 0) { Start-Sleep -Milliseconds $RemainingMilliseconds }
            }
            $RateTimer.Stop()

            $FinalRateSnapshot = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $FinalRateSnapshot -Names $Names
            Assert-CumulativeObservationMonotonic -Before $PreviousRateSnapshot -After $FinalRateSnapshot
            Assert-DetailedRateWindows -Snapshot $FinalRateSnapshot -ExpectedStates @('ready', 'ready', 'ready') -RequireTraffic
            foreach ($Role in @('external_xdp_ingress', 'physical_tc_egress')) {
                $InitialHook = Get-ObservationHook -Snapshot $InitialRateSnapshot -Role $Role
                $FinalHook = Get-ObservationHook -Snapshot $FinalRateSnapshot -Role $Role
                if ((Get-CheckedCounterDelta -Before $InitialHook.total.packets -After $FinalHook.total.packets -Evidence "$Role fixed rate traffic") -ne [uint64](65 * 9)) {
                    throw "fixed 1,170-frame rate matrix total changed for $Role"
                }
            }
        }
        'RateSamplingFailure' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds
            $BeforeSamplingFailure = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Start-Sleep -Seconds 4
            $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds
            $AfterSamplingFailure = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $AfterSamplingFailure -Names $Names -ExpectedHealth 'degraded'
            Assert-CumulativeObservationMonotonic -Before $BeforeSamplingFailure -After $AfterSamplingFailure
            Assert-DetailedRateWindows -Snapshot $AfterSamplingFailure -ExpectedStates @('stale', 'stale', 'stale')
            if ($AfterSamplingFailure.health -cne 'degraded' -or
                $null -ne $AfterSamplingFailure.sampling.latest_success_at_unix_ms -or
                $AfterSamplingFailure.sampling.last_error_code -cne 'OBS_MAP_UNAVAILABLE' -or
                [uint32]$AfterSamplingFailure.sampling.consecutive_failures -eq 0 -or
                [uint32]$AfterSamplingFailure.sampling.consecutive_failures -gt 10 -or
                $AfterSamplingFailure.sampling.sampling_paused) {
                throw 'background-only sampling failure diagnostics are invalid'
            }
            $FailureStatus = Convert-ObservationJson -Result (Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-StatusMatchesObservation -Status $FailureStatus -Snapshot $AfterSamplingFailure
            Assert-StatusRateWindows -Status $FailureStatus -ExpectedStates @('stale', 'stale', 'stale')
            $FailureInterface = Get-OnlyStatusInterface -Status $FailureStatus
            if ($FailureInterface.health -cne 'degraded' -or $FailureInterface.sampling.last_error_code -cne 'OBS_MAP_UNAVAILABLE') {
                throw 'status did not preserve bounded sampling failure diagnostics'
            }
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        }
        'RateGenerationReset' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $FirstGeneration = $null
            for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
                $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds
                Start-Sleep -Seconds 1
                $FirstGeneration = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
                if (@($FirstGeneration.rate_windows)[0].state -ceq 'ready') { break }
            }
            Assert-DetailedRateWindows -Snapshot $FirstGeneration -ExpectedStates @('ready', 'warming_up', 'warming_up')
            $FirstGenerationValue = [uint64]$FirstGeneration.generation

            $FirstDetachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
                "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-detach', '--run-id', $RunId
            )
            $FirstDetach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $FirstDetachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
            if ($FirstDetach.Stdout.Trim() -cne 'accepted') { throw 'first generation detach was not acknowledged' }
            $null = Invoke-IsolatedMutation -Phase 'links-down' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            try {
                Wait-IsolatedRemoteState -Phase 'snapshot-prepared' -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
            }
            catch {
                throw "first generation detach did not restore prepared state: $($_.Exception.Message)"
            }

            $SecondAttachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
                "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-attach', '--interface', $Names.HostVeth, '--run-id', $SecondRunId
            )
            $SecondAttach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $SecondAttachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
            if ($SecondAttach.Stdout.Trim() -cne 'accepted') { throw 'second generation attach was not acknowledged' }
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-second-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds

            $SecondGenerationInitial = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $SecondGenerationInitial -Names $Names
            if ([uint64]$SecondGenerationInitial.generation -eq $FirstGenerationValue) { throw 'interface generation did not change after exact reattach' }
            $SecondInitialOneSecondState = [string]@($SecondGenerationInitial.rate_windows)[0].state
            if ($SecondInitialOneSecondState -cnotin @('warming_up', 'ready')) {
                throw "second generation initial 1-second window had invalid state $SecondInitialOneSecondState"
            }
            Assert-DetailedRateWindows -Snapshot $SecondGenerationInitial -ExpectedStates @($SecondInitialOneSecondState, 'warming_up', 'warming_up')

            $SecondGenerationReady = $null
            for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
                $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount 1 -TimeoutSeconds $TimeoutSeconds
                Start-Sleep -Seconds 1
                $SecondGenerationReady = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
                if (@($SecondGenerationReady.rate_windows)[0].state -ceq 'ready') { break }
            }
            if ([uint64]$SecondGenerationReady.generation -ne [uint64]$SecondGenerationInitial.generation) { throw 'second generation identity changed while warming' }
            Assert-DetailedRateWindows -Snapshot $SecondGenerationReady -ExpectedStates @('ready', 'warming_up', 'warming_up')

            $SecondDetachArguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
                "$($Names.RemoteRunRoot)/l2-loopctl", 'isolated-detach', '--run-id', $SecondRunId
            )
            $SecondDetach = Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $SecondDetachArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
            if ($SecondDetach.Stdout.Trim() -cne 'accepted') { throw 'second generation detach was not acknowledged' }
            $null = Invoke-IsolatedMutation -Phase 'links-down' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            try {
                Wait-IsolatedRemoteState -Phase 'snapshot-prepared' -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
            }
            catch {
                throw "second generation detach did not restore prepared state: $($_.Exception.Message)"
            }
            $Detached = $true
        }
        'ObservationMapFailure' {
            $null = Invoke-IsolatedMutation -Phase 'links-up' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedMutation -Phase 'traffic-matrix' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $MapObservation = Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
            Assert-ObservationFailure -Result $MapObservation -Code 'OBS_MAP_UNAVAILABLE'
            $MapStatus = Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
            Assert-ObservationFailure -Result $MapStatus -Code 'OBS_MAP_UNAVAILABLE'
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
        }
        'ObservationIdentityChange' {
            $InitialObservation = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $InitialObservation -Names $Names
            $null = Invoke-IsolatedMutation -Phase 'alter-journal' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $ChangedObservation = Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
            Assert-ObservationFailure -Result $ChangedObservation -Code 'OBS_OWNERSHIP_MISMATCH'
            $ChangedStatus = Invoke-StatusCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json -AllowFailure
            Assert-ObservationFailure -Result $ChangedStatus -Code 'OBS_OWNERSHIP_MISMATCH'
            $null = Invoke-IsolatedMutation -Phase 'restore-journal' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $null = Invoke-IsolatedRemotePhase -Phase 'verify-hooks' -Names $Names -Target $Target -KeyPath $KeyPath -FrameCount $FrameCount -TimeoutSeconds $TimeoutSeconds
            $RestoredObservation = Convert-ObservationJson -Result (Invoke-ObservationCli -Names $Names -Target $Target -KeyPath $KeyPath -Interface $Names.HostVeth -TimeoutSeconds $TimeoutSeconds -Json)
            Assert-ObservationIdentity -Snapshot $RestoredObservation -Names $Names
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
