[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [ValidateRange(60, 1800)]
    [int] $TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$MAX_OUTPUT_BYTES = 1048576
$PERFORMANCE_FRAME_SIZES = @(64, 512, 1514)
$PERFORMANCE_FRAMES_PER_SIZE = 65536
$PERFORMANCE_TRIAL_COUNT = 5
$PERFORMANCE_PASS_THROUGH_MIN_PERMILLE = 950
$PERFORMANCE_OBSERVE_MIN_PERMILLE = 900
$PERFORMANCE_MAX_CPU_PERMILLE = 1000
$PERFORMANCE_MAX_RSS_BYTES = 268435456
$PERFORMANCE_MAX_RSS_GROWTH_BYTES = 16777216
$PERFORMANCE_TRIAL_ORDERS = @(
    @('baseline', 'pass_through', 'observe'),
    @('pass_through', 'observe', 'baseline'),
    @('observe', 'baseline', 'pass_through'),
    @('baseline', 'observe', 'pass_through'),
    @('pass_through', 'baseline', 'observe')
)
$STAGING_SCENARIOS = @(
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
)
$PERFORMANCE_FAILURE_SCENARIOS = @(
    'PerformancePassThroughRegression',
    'PerformanceObserveRegression',
    'PerformanceDropError',
    'PerformanceIncomplete',
    'PerformanceIdentityMismatch',
    'PerformanceCleanupMismatch'
)
$ExpectedBundleFiles = @(
    'deployment-v1.example.json',
    'l2-loop-deploycheck',
    'l2-loop-ebpf.o',
    'l2-loop-hostcheck',
    'l2-loop-install',
    'l2-loop.service',
    'l2-loopctl',
    'l2-loopd',
    'manifest.json',
    'SHA256SUMS'
)

# The checker invocation is fixed: 'staging' '--bundle' '--root' '--json'.

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $PSScriptRoot 'lib/IsolatedNames.psm1') -Force

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
    if ($Stdout.Length -gt $MAX_OUTPUT_BYTES -or $Stderr.Length -gt $MAX_OUTPUT_BYTES) {
        throw "$FilePath exceeded the bounded output size"
    }
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

function New-CryptographicRunId {
    $Bytes = [byte[]]::new(16)
    $Generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Generator.GetBytes($Bytes)
    }
    finally {
        $Generator.Dispose()
    }
    -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-ExactGreenDeploymentBundle {
    param([Parameter(Mandatory)] [string] $Commit)

    $RunQuery = Invoke-ExactProcess -FilePath 'gh' -ArgumentList @(
        'run', 'list', '--branch', 'main', '--commit', $Commit, '--limit', '10',
        '--json', 'databaseId,conclusion,headSha'
    ) -StandardInput $null -TimeoutSeconds 60
    $Run = @($RunQuery.Stdout | ConvertFrom-Json) |
        Where-Object { $null -ne $_ -and $_.headSha -ceq $Commit -and $_.conclusion -ceq 'success' } |
        Select-Object -First 1
    if ($null -eq $Run) {
        throw 'the exact commit does not have a successful GitHub Actions run'
    }

    $ArtifactRoot = Join-Path $RepositoryRoot ".artifacts/deployment-$Commit"
    if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
        $null = Invoke-ExactProcess -FilePath 'gh' -ArgumentList @(
            'run', 'download', [string]$Run.databaseId,
            '--name', "l2-loop-linux-x86_64-$Commit",
            '--dir', $ArtifactRoot
        ) -StandardInput $null -TimeoutSeconds 180
    }

    $RootItem = Get-Item -LiteralPath $ArtifactRoot
    Assert-NoSymlink -Item $RootItem
    $ObservedFiles = @(Get-ChildItem -LiteralPath $ArtifactRoot -Force)
    if ($ObservedFiles.Count -ne 10 -or @($ObservedFiles | Where-Object { $_.PSIsContainer }).Count -ne 0) {
        throw 'deployment bundle inventory is not exactly ten regular files'
    }
    $ObservedNames = @($ObservedFiles.Name | Sort-Object)
    $ExpectedNames = @($ExpectedBundleFiles | Sort-Object)
    if (($ObservedNames -join "`n") -cne ($ExpectedNames -join "`n")) {
        throw 'deployment bundle filenames do not match the fixed inventory'
    }

    $ChecksumLines = @(Get-Content -LiteralPath (Join-Path $ArtifactRoot 'SHA256SUMS'))
    if ($ChecksumLines.Count -ne 9) {
        throw 'deployment checksum file must contain exactly nine entries'
    }
    $Covered = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($Line in $ChecksumLines) {
        if ($Line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') {
            throw 'deployment checksum line is malformed'
        }
        $ExpectedHash = $Matches[1]
        $Filename = $Matches[2]
        if ($Filename -ceq 'SHA256SUMS' -or $Filename -cnotin $ExpectedBundleFiles -or -not $Covered.Add($Filename)) {
            throw 'deployment checksum coverage is invalid'
        }
        $Item = Get-Item -LiteralPath (Join-Path $ArtifactRoot $Filename)
        Assert-NoSymlink -Item $Item
        if ($Item.PSIsContainer) { throw 'deployment bundle payload is not a regular file' }
        $ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName).Hash.ToLowerInvariant()
        if ($ActualHash -cne $ExpectedHash) {
            throw "deployment bundle checksum mismatch for $Filename"
        }
    }

    $Manifest = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'manifest.json') -Raw | ConvertFrom-Json
    if ($Manifest.commit_sha -cne $Commit -or
        $Manifest.files.deployment_checker -cne 'l2-loop-deploycheck' -or
        $Manifest.files.installer -cne 'l2-loop-install') {
        throw 'deployment manifest identity does not match the exact artifact'
    }
    [pscustomobject]@{
        Root = $ArtifactRoot
        PackageVersion = [string]$Manifest.package_version
        RunId = [uint64]$Run.databaseId
    }
}

$RemoteProgram = @'
set -Eeuo pipefail

phase=$1
run=$2
ns=$3
host=$4
peer=$5
root=$6
bundle=$7
staging=$8
commit=$9
scenario=${10}
trap 'status=$?; printf "remote phase failed: phase=%s scenario=%s line=%s status=%s\n" "$phase" "$scenario" "$LINENO" "$status" >&2; exit "$status"' ERR
journal="/run/l2-loop/tests/$run.json"
pins="/sys/fs/bpf/l2-loop/test/$run"
evidence="$root/evidence/v1"
checker="$bundle/l2-loop-deploycheck"
runtime_marker="$root/.owned-runtime-parent"
accept_marker="$root/.owned-accept-parent"

fail() { printf '%s\n' "$1" >&2; exit 1; }
assert_no_symlink() { test ! -L "$1" || fail "owned path is a symbolic link"; }
assert_generated() {
    case "$run" in *[!0-9a-f]*|'') fail "run ID is not generated" ;; esac
    test "${#run}" -eq 32 || fail "run ID length is invalid"
    test "$(printf '%.12s' "$run")" = "${ns#l2ns-}" || fail "namespace is not generated"
    test "$(printf '%.10s' "$run")" = "${host#l2h}" || fail "host veth is not generated"
    test "$(printf '%.10s' "$run")" = "${peer#l2n}" || fail "peer veth is not generated"
    test "$root" = "/run/l2-loop/accept/$run" || fail "run root is not generated"
    test "$bundle" = "$root/bundle" || fail "bundle root is not generated"
    test "$staging" = "$root/staging-root" || fail "staging root is not generated"
}
assert_owned_path() {
    path=$1
    case "$path" in "$root"|"$root"/*) ;; *) fail "owned path escaped the generated root" ;; esac
    case "$path" in *'/../'*|*'/./'*|*/..|*/.) fail "owned path is not canonical" ;; esac
}
assert_generated

snapshot() {
    ebpf=$("$bundle/l2-loop-hostcheck" snapshot | sha256sum | awk '{print $1}')
    links=$(ip -j link show | sha256sum | awk '{print $1}')
    routes=$(ip -j route show table all | sha256sum | awk '{print $1}')
    printf '{"ebpf_identity":"%s","network_links":"%s","network_routes":"%s"}\n' "$ebpf" "$links" "$routes"
}

snapshot_prepared() {
    ebpf=$("$bundle/l2-loop-hostcheck" snapshot | sha256sum | awk '{print $1}')
    links=$(ip -j link show | python3 -c 'import json,sys; excluded=sys.argv[1]; value=json.load(sys.stdin); matches=[item for item in value if item.get("ifname")==excluded]; len(matches)!=1 and sys.exit("generated host veth is not unique"); filtered=[item for item in value if item.get("ifname")!=excluded]; print(json.dumps(filtered,sort_keys=True,separators=(",",":")))' "$host" | sha256sum | awk '{print $1}')
    routes=$(ip -j route show table all | sha256sum | awk '{print $1}')
    printf '{"ebpf_identity":"%s","network_links":"%s","network_routes":"%s"}\n' "$ebpf" "$links" "$routes"
}

cleanup_file() {
    path=$1
    assert_owned_path "$path"
    if test -e "$path" || test -L "$path"; then unlink "$path"; fi
}
cleanup_dir() {
    path=$1
    assert_owned_path "$path"
    if test -d "$path" || test -L "$path"; then
        assert_no_symlink "$path"
        resolved=$(readlink -f "$path")
        case "$resolved" in "$root"|"$root"/*) ;; *) fail "resolved-prefix cleanup check failed" ;; esac
        rmdir "$path"
    fi
}
stop_owned_process() {
    pid_file=$1
    expected=$2
    if test -f "$pid_file" && test ! -L "$pid_file"; then
        pid=$(cat "$pid_file")
        case "$pid" in *[!0-9]*|'') fail "owned PID is invalid" ;; esac
        if test -e "/proc/$pid/exe"; then
            actual=$(readlink "/proc/$pid/exe")
            test "$actual" = "$expected" || fail "owned PID identity changed"
            kill -TERM "$pid"
            tries=0
            while kill -0 "$pid" 2>/dev/null && test "$tries" -lt 100; do
                state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || printf X)
                test "$state" != Z || break
                sleep 0.1
                tries=$((tries + 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || printf X)
                test "$state" = Z || fail "owned process did not stop"
            fi
        fi
    fi
}
cleanup_pins() {
    for name in IFACE_CONFIG HOOK_STATS FINGERPRINTS PROBE_REGISTRY PROBE_STATS RATE_POLICY; do
        if test -e "$pins/$name" || test -L "$pins/$name"; then unlink "$pins/$name"; fi
    done
    if test -d "$pins"; then rmdir "$pins"; fi
    if test -d /sys/fs/bpf/l2-loop/test; then rmdir /sys/fs/bpf/l2-loop/test 2>/dev/null || true; fi
    if test -d /sys/fs/bpf/l2-loop; then rmdir /sys/fs/bpf/l2-loop 2>/dev/null || true; fi
    if test -e "$journal" || test -L "$journal"; then unlink "$journal"; fi
    if test -d /run/l2-loop/tests; then rmdir /run/l2-loop/tests 2>/dev/null || true; fi
}
cleanup_scenario_bundle() {
    scenario_bundle="$root/scenario-bundle"
    for name in deployment-v1.example.json l2-loop-deploycheck l2-loop-ebpf.o l2-loop-hostcheck l2-loop-install l2-loop.service l2-loopctl l2-loopd manifest.json SHA256SUMS unexpected; do
        cleanup_file "$scenario_bundle/$name"
    done
    cleanup_dir "$scenario_bundle"
}
cleanup_staging_tree() {
    cleanup_file "$staging/run/l2-loop/agent.sock"
    cleanup_file "$staging/etc/l2-loop/deployment-v1.json"
    cleanup_file "$staging/var/lib/l2-loop/gates/performance-v1.json"
    cleanup_file "$staging/usr/bin/l2-loopctl"
    cleanup_file "$staging/usr/libexec/l2-loop/l2-loopd"
    cleanup_file "$staging/usr/libexec/l2-loop/l2-loop-deploycheck"
    cleanup_file "$staging/usr/libexec/l2-loop/l2-loop-install"
    cleanup_file "$staging/usr/libexec/l2-loop/l2-loop-hostcheck"
    cleanup_file "$staging/usr/libexec/l2-loop/l2-loop-ebpf.o"
    cleanup_file "$staging/usr/libexec/l2-loop/manifest.json"
    cleanup_file "$staging/usr/libexec/l2-loop/SHA256SUMS"
    cleanup_file "$staging/usr/lib/systemd/system/l2-loop.service"
    cleanup_file "$staging/usr/share/doc/l2-loop/deployment-v1.example.json"
    cleanup_dir "$staging/run/l2-loop"
    cleanup_dir "$staging/run"
    cleanup_dir "$staging/var/lib/l2-loop/gates"
    cleanup_dir "$staging/var/lib/l2-loop/evidence/v1"
    cleanup_dir "$staging/var/lib/l2-loop/evidence"
    cleanup_dir "$staging/var/lib/l2-loop"
    cleanup_dir "$staging/var/lib"
    cleanup_dir "$staging/var"
    cleanup_dir "$staging/etc/l2-loop"
    cleanup_dir "$staging/etc"
    cleanup_dir "$staging/usr/share/doc/l2-loop"
    cleanup_dir "$staging/usr/share/doc"
    cleanup_dir "$staging/usr/share"
    cleanup_dir "$staging/usr/lib/systemd/system"
    cleanup_dir "$staging/usr/lib/systemd"
    cleanup_dir "$staging/usr/lib"
    cleanup_dir "$staging/usr/libexec/l2-loop"
    cleanup_dir "$staging/usr/libexec"
    cleanup_dir "$staging/usr/bin"
    cleanup_dir "$staging/usr"
    cleanup_dir "$staging"
}
cleanup_generated_tree() {
    owned_runtime_parent=0
    owned_accept_parent=0
    if test -e "$runtime_marker" || test -L "$runtime_marker"; then
        assert_no_symlink "$runtime_marker"
        test -f "$runtime_marker" || fail "runtime parent ownership marker is not a regular file"
        test "$(stat -c '%u:%g:%a:%s' "$runtime_marker")" = '0:0:600:0' || fail "runtime parent ownership marker identity changed"
        owned_runtime_parent=1
    fi
    if test -e "$accept_marker" || test -L "$accept_marker"; then
        assert_no_symlink "$accept_marker"
        test -f "$accept_marker" || fail "accept parent ownership marker is not a regular file"
        test "$(stat -c '%u:%g:%a:%s' "$accept_marker")" = '0:0:600:0' || fail "accept parent ownership marker identity changed"
        owned_accept_parent=1
    fi
    if test "$owned_runtime_parent" -eq 1 && test "$owned_accept_parent" -ne 1; then
        fail "runtime parent ownership is incomplete"
    fi
    stop_owned_process "$root/daemon.pid" "$bundle/l2-loopd"
    stop_owned_process "$root/pass-through.pid" "$root/l2-loop-hostcheck"
    if ip link show dev "$host" >/dev/null 2>&1; then
        kind=$(ip -j -details link show dev "$host" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0].get("linkinfo",{}).get("info_kind",""))')
        test "$kind" = veth || fail "generated host cleanup identity changed"
        ip link delete dev "$host"
    fi
    if ip netns list | awk '{print $1}' | grep -Fqx -- "$ns"; then ip netns delete "$ns"; fi
    cleanup_pins
    final_state=$(snapshot)
    cleanup_scenario_bundle
    cleanup_staging_tree
    cleanup_file "$root/pass-through.fifo"
    cleanup_file "$root/pass-through.out"
    cleanup_file "$root/pass-through.pid"
    cleanup_file "$root/daemon.pid"
    cleanup_file "$root/daemon.log"
    cleanup_file "$root/trial.json"
    cleanup_file "$root/checker.err"
    cleanup_file "$root/l2-loop-hostcheck"
    cleanup_file "$root/l2-loop-ebpf.o"
    cleanup_file "$runtime_marker"
    cleanup_file "$accept_marker"
    cleanup_dir "$root/evidence/v1"
    cleanup_dir "$root/evidence"
    for name in deployment-v1.example.json l2-loop-deploycheck l2-loop-ebpf.o l2-loop-hostcheck l2-loop-install l2-loop.service l2-loopctl l2-loopd manifest.json SHA256SUMS; do
        cleanup_file "$bundle/$name"
    done
    cleanup_dir "$bundle"
    cleanup_dir "$root"
    if test "$owned_accept_parent" -eq 1; then rmdir /run/l2-loop/accept; fi
    if test "$owned_runtime_parent" -eq 1; then rmdir /run/l2-loop; fi
    printf '%s\n' "$final_state"
}

install_layout() {
    install -d -m 0700 "$staging"
    install -d -m 0755 "$staging/usr" "$staging/usr/bin" "$staging/usr/lib" "$staging/usr/libexec" "$staging/usr/libexec/l2-loop" "$staging/usr/lib/systemd" "$staging/usr/lib/systemd/system" "$staging/usr/share" "$staging/usr/share/doc" "$staging/usr/share/doc/l2-loop" "$staging/etc" "$staging/var" "$staging/var/lib" "$staging/run"
    install -d -m 0700 "$staging/etc/l2-loop" "$staging/var/lib/l2-loop" "$staging/var/lib/l2-loop/gates" "$staging/var/lib/l2-loop/evidence" "$staging/var/lib/l2-loop/evidence/v1" "$staging/run/l2-loop"
    install -m 0755 "$bundle/l2-loopctl" "$staging/usr/bin/l2-loopctl"
    install -m 0755 "$bundle/l2-loopd" "$staging/usr/libexec/l2-loop/l2-loopd"
    install -m 0755 "$bundle/l2-loop-deploycheck" "$staging/usr/libexec/l2-loop/l2-loop-deploycheck"
    install -m 0755 "$bundle/l2-loop-install" "$staging/usr/libexec/l2-loop/l2-loop-install"
    install -m 0755 "$bundle/l2-loop-hostcheck" "$staging/usr/libexec/l2-loop/l2-loop-hostcheck"
    install -m 0644 "$bundle/l2-loop-ebpf.o" "$staging/usr/libexec/l2-loop/l2-loop-ebpf.o"
    install -m 0644 "$bundle/manifest.json" "$staging/usr/libexec/l2-loop/manifest.json"
    install -m 0644 "$bundle/SHA256SUMS" "$staging/usr/libexec/l2-loop/SHA256SUMS"
    install -m 0644 "$bundle/l2-loop.service" "$staging/usr/lib/systemd/system/l2-loop.service"
    install -m 0644 "$bundle/deployment-v1.example.json" "$staging/usr/share/doc/l2-loop/deployment-v1.example.json"
    python3 - "$staging" "$commit" "$bundle/manifest.json" <<'PY'
import json, os, sys, time
root, commit, manifest_path = sys.argv[1:]
with open(manifest_path, "r", encoding="utf-8") as channel:
    package = json.load(channel)["package_version"]
now = int(time.time() * 1000)
authorization = {
    "schema_version": 1,
    "authorization_id": "0123456789abcdef0123456789abcdef",
    "artifact_commit_sha": commit,
    "mode": "read_only_canary_candidate",
    "interface": {
        "name": "spare0", "ifindex": 7, "kind": "physical",
        "administrative_state": "up", "operational_state": "up",
        "master_ifindex": None,
        "mac_address_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "driver": "test_driver",
        "device_identity_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "network_namespace_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "xdp_native": "empty", "xdp_generic": "empty",
        "tc_clsact": False, "tc_ingress": [], "tc_egress": []
    },
    "issued_at_unix_ms": now - 1000,
    "expires_at_unix_ms": now + 3600000
}
orders = [
    ["baseline", "pass_through", "observe"],
    ["pass_through", "observe", "baseline"],
    ["observe", "baseline", "pass_through"],
    ["baseline", "observe", "pass_through"],
    ["pass_through", "baseline", "observe"]
]
trials = []
for number, order in enumerate(orders, 1):
    for mode in order:
        trials.append({
            "trial_number": number, "mode": mode, "frame_sizes": [64, 512, 1514],
            "frames_per_size": 65536, "duration_ns": 1000000000,
            "packets_per_second": 196608, "bytes_per_second": 136970240,
            "daemon_cpu_time_ns": 0, "peak_resident_memory_bytes": 1048576,
            "packet_drop_delta": 0, "packet_error_delta": 0
        })
rate = {"packets_per_second": 196608, "bytes_per_second": 136970240}
performance = {
    "schema_version": 1, "evidence_id": "fedcba9876543210fedcba9876543210",
    "artifact_commit_sha": commit, "package_version": package,
    "architecture": "x86_64", "kernel_release": "fixture-kernel", "logical_cpu_count": 1,
    "veth_xdp_mode": "generic", "issued_at_unix_ms": now - 1000,
    "expires_at_unix_ms": now + 3600000, "warm_up_complete": True,
    "measurement_complete": True, "measurement_noisy": False, "host_identity_stable": True,
    "trials": trials, "medians": {"baseline": rate, "pass_through": rate, "observe": rate},
    "pass_through_baseline_ratio_permille": 1000, "observe_baseline_ratio_permille": 1000,
    "daemon_cpu_time_ns": 0, "daemon_cpu_permille": 0,
    "peak_resident_memory_bytes": 1048576, "rss_growth_bytes": 0,
    "packet_drop_delta": 0, "packet_error_delta": 0,
    "process_count_before": 0, "process_count_after": 0,
    "map_count_before": 0, "map_count_after": 0,
    "program_count_before": 0, "program_count_after": 0,
    "pin_count_before": 0, "pin_count_after": 0,
    "namespace_count_before": 0, "namespace_count_after": 0,
    "forwarding_intact": True, "owned_cleanup_complete": True,
    "network_identity_restored": True, "ebpf_identity_restored": True,
    "result": "passed", "findings": []
}
for relative, value in [
    ("etc/l2-loop/deployment-v1.json", authorization),
    ("var/lib/l2-loop/gates/performance-v1.json", performance)
]:
    path = os.path.join(root, relative)
    with open(path, "w", encoding="utf-8") as channel:
        json.dump(value, channel, sort_keys=True, separators=(",", ":"))
    os.chmod(path, 0o600)
PY
}

rebind_hardened_unit_fixture() {
    scenario_bundle="$root/scenario-bundle"
    install -d -m 0700 "$scenario_bundle"
    for name in deployment-v1.example.json l2-loop-deploycheck l2-loop-ebpf.o l2-loop-hostcheck l2-loop-install l2-loop.service l2-loopctl l2-loopd manifest.json SHA256SUMS; do
        install -m 0600 "$bundle/$name" "$scenario_bundle/$name"
    done
    python3 - "$scenario_bundle" <<'PY'
import hashlib, json, os, sys
root = sys.argv[1]
unit_path = os.path.join(root, "l2-loop.service")
with open(unit_path, "r", encoding="utf-8") as channel:
    unit = channel.read()
if unit.count("Restart=no") != 1:
    raise SystemExit("service fixture restart identity changed")
unit = unit.replace("Restart=no", "Restart=always")
with open(unit_path, "w", encoding="utf-8", newline="") as channel:
    channel.write(unit)
unit_digest = hashlib.sha256(unit.encode("utf-8")).hexdigest()
manifest_path = os.path.join(root, "manifest.json")
with open(manifest_path, "r", encoding="utf-8") as channel:
    manifest = json.load(channel)
manifest["service_unit_sha256"] = unit_digest
with open(manifest_path, "w", encoding="utf-8", newline="") as channel:
    json.dump(manifest, channel, sort_keys=True, separators=(",", ":"))
payloads = [
    "deployment-v1.example.json", "l2-loop-deploycheck", "l2-loop-ebpf.o",
    "l2-loop-hostcheck", "l2-loop-install", "l2-loop.service", "l2-loopctl", "l2-loopd", "manifest.json"
]
with open(os.path.join(root, "SHA256SUMS"), "w", encoding="ascii", newline="") as channel:
    for name in sorted(payloads):
        with open(os.path.join(root, name), "rb") as payload:
            digest = hashlib.sha256(payload.read()).hexdigest()
        channel.write("%s  %s\n" % (digest, name))
PY
    install -m 0644 "$scenario_bundle/l2-loop.service" "$staging/usr/lib/systemd/system/l2-loop.service"
    install -m 0644 "$scenario_bundle/manifest.json" "$staging/usr/libexec/l2-loop/manifest.json"
    install -m 0644 "$scenario_bundle/SHA256SUMS" "$staging/usr/libexec/l2-loop/SHA256SUMS"
}

run_checker_positive() {
    if output=$("$checker" staging --bundle "$bundle" --root "$staging" --json 2>"$root/checker.err"); then
        status=0
    else
        status=$?
    fi
    test "${#output}" -le 1048576 || fail "checker output exceeded the fixed bound"
    if test "$status" -ne 0; then
        printf '%s' "$output" | python3 -c 'import json,sys; value=json.load(sys.stdin); codes=sorted(str(item.get("code")) for item in value.get("findings",[])); print("positive checker blocked: decision=%s codes=%s"%(value.get("decision"),",".join(codes)),file=sys.stderr)'
        fail "positive checker rejected generated evidence"
    fi
    printf '%s' "$output" | python3 -c 'import json,sys; value=json.load(sys.stdin); value.get("decision")!="staging_ready" and sys.exit("staging decision was not positive"); value.get("mutations_performed") is not False and sys.exit("checker reported a mutation")'
    "$checker" staging --bundle "$bundle" --root "$staging" >/dev/null
    unlink "$root/checker.err"
}

run_checker_blocked() {
    selected_bundle=$1
    expected=$2
    if output=$("$checker" staging --bundle "$selected_bundle" --root "$staging" --json 2>"$root/checker.err"); then
        status=0
    else
        status=$?
    fi
    test "$status" -eq 4 || fail "negative checker scenario did not return exit code 4"
    test "${#output}" -le 1048576 || fail "negative checker output exceeded the fixed bound"
    printf '%s' "$output" | python3 -c 'import json,sys; expected=sys.argv[1]; scenario=sys.argv[2]; value=json.load(sys.stdin); codes=[item.get("code") for item in value.get("findings",[])]; value.get("decision")!="blocked" and sys.exit("negative scenario was not blocked: "+scenario); codes!=[expected] and sys.exit("negative scenario finding changed: %s expected %s got %s"%(scenario,expected,",".join(str(code) for code in codes)))' "$expected" "$scenario"
    unlink "$root/checker.err"
}

stage_negative() {
    cleanup_scenario_bundle
    case "$scenario" in
        ChecksumMismatch|ExtraFile)
            install -d -m 0700 "$root/scenario-bundle"
            for name in deployment-v1.example.json l2-loop-deploycheck l2-loop-ebpf.o l2-loop-hostcheck l2-loop-install l2-loop.service l2-loopctl l2-loopd manifest.json SHA256SUMS; do install -m 0600 "$bundle/$name" "$root/scenario-bundle/$name"; done
            if test "$scenario" = ChecksumMismatch; then printf 'x' >>"$root/scenario-bundle/l2-loopd"; else printf 'x' >"$root/scenario-bundle/unexpected"; fi
            run_checker_blocked "$root/scenario-bundle" DG_ARTIFACT_INVENTORY
            cleanup_scenario_bundle
            ;;
        Symlink)
            unlink "$staging/usr/libexec/l2-loop/l2-loop-ebpf.o"
            ln -s "$bundle/l2-loop-ebpf.o" "$staging/usr/libexec/l2-loop/l2-loop-ebpf.o"
            run_checker_blocked "$bundle" DG_LAYOUT_TYPE
            unlink "$staging/usr/libexec/l2-loop/l2-loop-ebpf.o"
            install -m 0644 "$bundle/l2-loop-ebpf.o" "$staging/usr/libexec/l2-loop/l2-loop-ebpf.o"
            ;;
        WrongMode)
            chmod 0644 "$staging/usr/libexec/l2-loop/l2-loopd"
            run_checker_blocked "$bundle" DG_LAYOUT_TYPE
            chmod 0755 "$staging/usr/libexec/l2-loop/l2-loopd"
            ;;
        OccupiedRuntime)
            printf 'occupied' >"$staging/run/l2-loop/agent.sock"
            run_checker_blocked "$bundle" DG_LAYOUT_TYPE
            unlink "$staging/run/l2-loop/agent.sock"
            ;;
        MalformedAuthorization)
            printf '{' >"$staging/etc/l2-loop/deployment-v1.json"
            chmod 0600 "$staging/etc/l2-loop/deployment-v1.json"
            run_checker_blocked "$bundle" DG_AUTH_SCHEMA
            install_layout
            ;;
        ExpiredAuthorization)
            python3 - "$staging/etc/l2-loop/deployment-v1.json" <<'PY'
import json, sys, time
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as channel: value=json.load(channel)
now=int(time.time()*1000); value["issued_at_unix_ms"]=now-2000; value["expires_at_unix_ms"]=now-1000
with open(path, "w", encoding="utf-8") as channel: json.dump(value, channel, sort_keys=True, separators=(",",":"))
PY
            run_checker_blocked "$bundle" DG_AUTH_EXPIRED
            install_layout
            ;;
        MalformedPerformance)
            printf '{' >"$staging/var/lib/l2-loop/gates/performance-v1.json"
            chmod 0600 "$staging/var/lib/l2-loop/gates/performance-v1.json"
            run_checker_blocked "$bundle" DG_PERFORMANCE_UNAVAILABLE
            install_layout
            ;;
        HardenedUnitFailure)
            rebind_hardened_unit_fixture
            run_checker_blocked "$root/scenario-bundle" DG_SYSTEMD_CONTRACT
            install -m 0644 "$bundle/l2-loop.service" "$staging/usr/lib/systemd/system/l2-loop.service"
            install -m 0644 "$bundle/manifest.json" "$staging/usr/libexec/l2-loop/manifest.json"
            install -m 0644 "$bundle/SHA256SUMS" "$staging/usr/libexec/l2-loop/SHA256SUMS"
            cleanup_scenario_bundle
            ;;
        *) fail "unknown staging scenario" ;;
    esac
}

link_stat() {
    location=$1
    interface=$2
    if test "$location" = root; then
        ip -j -s link show dev "$interface"
    else
        ip netns exec "$ns" ip -j -s link show dev "$interface"
    fi
}
send_frames() {
    location=$1
    interface=$2
    count=$3
    size=$4
    destination=$5
    direction=$6
    sender='import socket,sys; interface=sys.argv[1]; count=int(sys.argv[2]); size=int(sys.argv[3]); destination=bytes.fromhex(sys.argv[4].replace(":","")); source=bytes.fromhex(open("/sys/class/net/%s/address"%interface,"r",encoding="ascii").read().strip().replace(":","")); marker=bytes([int(sys.argv[5])]); arp=b"\x00\x01\x08\x00\x06\x04\x00\x01"+source+bytes(4)+destination+bytes(4); frame=destination+source+b"\x08\x06"+arp+marker+bytes(size-43); channel=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); channel.bind((interface,0)); [channel.send(frame) for _ in range(count)]; channel.close()'
    if test "$location" = root; then python3 -c "$sender" "$interface" "$count" "$size" "$destination" "$direction"; else ip netns exec "$ns" python3 -c "$sender" "$interface" "$count" "$size" "$destination" "$direction"; fi
}
measure_traffic() {
    per_direction=$((PER_SIZE / 2))
    host_mac=$(cat "/sys/class/net/$host/address")
    peer_mac=$(ip netns exec "$ns" cat "/sys/class/net/$peer/address")
    before_host=$(link_stat root "$host")
    before_peer=$(link_stat netns "$peer")
    started=$(date +%s%N)
    for size in 64 512 1514; do
        send_frames netns "$peer" "$per_direction" "$size" "$host_mac" 1
        send_frames root "$host" "$per_direction" "$size" "$peer_mac" 2
    done
    ended=$(date +%s%N)
    after_host=$(link_stat root "$host")
    after_peer=$(link_stat netns "$peer")
    python3 - "$started" "$ended" "$PER_SIZE" "$before_host" "$after_host" "$before_peer" "$after_peer" <<'PY'
import json, sys
started, ended, per_size = map(int, sys.argv[1:4])
before_host, after_host, before_peer, after_peer = map(json.loads, sys.argv[4:8])
def counters(value):
    stats=value[0]["stats64"]
    return {"rx_packets":stats["rx"]["packets"],"rx_errors":stats["rx"]["errors"],"rx_dropped":stats["rx"]["dropped"],"tx_errors":stats["tx"]["errors"],"tx_dropped":stats["tx"]["dropped"]}
bh, ah, bp, ap = map(counters, [before_host, after_host, before_peer, after_peer])
duration=ended-started
packets=per_size*3
logical_bytes=per_size*(64+512+1514)
drops=(ah["rx_dropped"]-bh["rx_dropped"])+(ah["tx_dropped"]-bh["tx_dropped"])+(ap["rx_dropped"]-bp["rx_dropped"])+(ap["tx_dropped"]-bp["tx_dropped"])
errors=(ah["rx_errors"]-bh["rx_errors"])+(ah["tx_errors"]-bh["tx_errors"])+(ap["rx_errors"]-bp["rx_errors"])+(ap["tx_errors"]-bp["tx_errors"])
forwarding=(ah["rx_packets"]-bh["rx_packets"]==packets//2 and ap["rx_packets"]-bp["rx_packets"]==packets//2)
print(json.dumps({"duration_ns":duration,"packets_per_second":packets*1000000000//duration,"bytes_per_second":logical_bytes*1000000000//duration,"packet_drop_delta":drops,"packet_error_delta":errors,"forwarding_intact":forwarding},sort_keys=True,separators=(",",":")))
PY
}
proc_metrics() {
    pid=$1
    python3 - "$pid" <<'PY'
import os, sys
pid=sys.argv[1]
with open("/proc/%s/stat"%pid,"r",encoding="ascii") as channel: fields=channel.read().split()
ticks=int(fields[13])+int(fields[14]); hz=os.sysconf(os.sysconf_names["SC_CLK_TCK"]); cpu=ticks*1000000000//hz
peak=0
with open("/proc/%s/status"%pid,"r",encoding="ascii") as channel:
    for line in channel:
        if line.startswith("VmHWM:"): peak=int(line.split()[1])*1024
print("%d %d"%(cpu,peak))
PY
}
wait_owned_exit() {
    pid=$1
    tries=0
    while kill -0 "$pid" 2>/dev/null && test "$tries" -lt 100; do
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || printf X)
        test "$state" != Z || break
        sleep 0.1
        tries=$((tries + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || printf X)
        test "$state" = Z || fail "owned process exceeded the bounded exit wait"
    fi
    wait "$pid"
}
start_pass_through() {
    ulimit -l unlimited
    rm_fifo="$root/pass-through.fifo"
    test ! -e "$rm_fifo" && test ! -L "$rm_fifo" || fail "pass-through control path is occupied"
    mkfifo -m 0600 "$rm_fifo"
    "$root/l2-loop-hostcheck" pass-through --acceptance-only pass-through-v1 --run-id "$run" --evidence-root "$evidence" --interface "$host" --ifindex "$(cat /sys/class/net/$host/ifindex)" <"$rm_fifo" >"$root/pass-through.out" &
    pass_pid=$!
    printf '%s\n' "$pass_pid" >"$root/pass-through.pid"
    exec 3>"$rm_fifo"
    tries=0
    while ! grep -Fq '"state":"ready"' "$root/pass-through.out" && test "$tries" -lt 100; do sleep 0.1; tries=$((tries + 1)); done
    if ! grep -Fq '"state":"ready"' "$root/pass-through.out"; then
        fail "pass-through did not become ready"
    fi
}
stop_pass_through() {
    printf 'stop\n' >&3
    exec 3>&-
    wait_owned_exit "$pass_pid"
    grep -Fq '"state":"cleaned"' "$root/pass-through.out" || fail "pass-through cleanup state is missing"
    unlink "$root/pass-through.pid"
    unlink "$root/pass-through.out"
    unlink "$root/pass-through.fifo"
}
start_observe() {
    cd "$bundle"
    ulimit -l unlimited
    env L2_LOOP_ACCEPTANCE_EVIDENCE_ROOT="$evidence" ./l2-loopd >"$root/daemon.log" 2>&1 &
    daemon_pid=$!
    printf '%s\n' "$daemon_pid" >"$root/daemon.pid"
    tries=0
    while test ! -S /run/l2-loop/agent.sock && test "$tries" -lt 100; do sleep 0.1; tries=$((tries + 1)); done
    test -S /run/l2-loop/agent.sock || fail "observe daemon socket was not created"
    if ! attach_output=$("$bundle/l2-loopctl" isolated-attach --interface "$host" --run-id "$run" 2>&1); then
        printf '%s\n' "$attach_output" >&2
        fail "observe attach was rejected"
    fi
    test "$attach_output" = accepted || fail "observe attach acknowledgement changed"
}
stop_observe() {
    if ! detach_output=$("$bundle/l2-loopctl" isolated-detach --run-id "$run" 2>&1); then
        printf '%s\n' "$detach_output" >&2
        fail "observe detach was rejected"
    fi
    test "$detach_output" = accepted || fail "observe detach acknowledgement changed"
    kill -TERM "$daemon_pid"
    wait_owned_exit "$daemon_pid"
    unlink "$root/daemon.pid"
    unlink "$root/daemon.log"
    test ! -e /run/l2-loop/agent.sock && test ! -L /run/l2-loop/agent.sock || fail "observe daemon socket remained"
}
run_measurement() {
    mode=$scenario
    ip link set dev "$host" down
    ip netns exec "$ns" ip link set dev "$peer" down
    process_pid=''
    case "$mode" in
        baseline) ;;
        pass_through) start_pass_through; process_pid=$pass_pid ;;
        observe) start_observe; process_pid=$daemon_pid ;;
        *) fail "unknown performance mode" ;;
    esac
    cpu_before=0
    peak=0
    if test -n "$process_pid"; then set -- $(proc_metrics "$process_pid"); cpu_before=$1; peak=$2; fi
    ip link set dev "$host" up
    ip netns exec "$ns" ip link set dev "$peer" up
    PER_SIZE=65536
    traffic=$(measure_traffic)
    if test -n "$process_pid"; then set -- $(proc_metrics "$process_pid"); cpu_after=$1; observed_peak=$2; test "$observed_peak" -le "$peak" || peak=$observed_peak; else cpu_after=0; fi
    ip link set dev "$host" down
    ip netns exec "$ns" ip link set dev "$peer" down
    case "$mode" in baseline) ;; pass_through) stop_pass_through ;; observe) stop_observe ;; esac
    cleanup_pins
    printf '%s' "$traffic" | python3 -c 'import json,sys; value=json.load(sys.stdin); value["daemon_cpu_time_ns"]=int(sys.argv[1])-int(sys.argv[2]); value["peak_resident_memory_bytes"]=int(sys.argv[3]); print(json.dumps(value,sort_keys=True,separators=(",",":")))' "$cpu_after" "$cpu_before" "$peak"
}

case "$phase" in
    precheck)
        test "$(id -u)" -eq 0 || fail "deployment acceptance requires root"
        for command_name in ip python3 sha256sum awk grep install chmod readlink kill sleep cat unlink env date mkfifo nproc uname stat mkdir rmdir; do command -v "$command_name" >/dev/null || fail "required acceptance command is unavailable"; done
        test ! -e "$root" && test ! -L "$root" || fail "generated run root already exists"
        test ! -e "$journal" && test ! -L "$journal" || fail "generated journal already exists"
        test ! -e "$pins" && test ! -L "$pins" || fail "generated pin root already exists"
        test ! -e /run/l2-loop/agent.sock && test ! -L /run/l2-loop/agent.sock || fail "daemon socket is occupied"
        ! ip link show dev "$host" >/dev/null 2>&1 || fail "generated host veth already exists"
        ! ip netns list | awk '{print $1}' | grep -Fqx -- "$ns" || fail "generated namespace already exists"
        ;;
    create-root)
        runtime_created=0
        accept_created=0
        trap 'status=$?; if test "$status" -ne 0; then if test -f "$runtime_marker" && test ! -L "$runtime_marker"; then unlink "$runtime_marker"; fi; if test -f "$accept_marker" && test ! -L "$accept_marker"; then unlink "$accept_marker"; fi; rmdir "$evidence" "$root/evidence" "$bundle" "$root" 2>/dev/null || true; if test "$accept_created" -eq 1; then rmdir /run/l2-loop/accept 2>/dev/null || true; fi; if test "$runtime_created" -eq 1; then rmdir /run/l2-loop 2>/dev/null || true; fi; fi; exit "$status"' EXIT
        if test -e /run/l2-loop || test -L /run/l2-loop; then
            assert_no_symlink /run/l2-loop
            test -d /run/l2-loop || fail "runtime parent is not a directory"
            test "$(stat -c '%u:%g:%a' /run/l2-loop)" = '0:0:700' || fail "runtime parent metadata is unsafe"
        else
            mkdir -m 0700 /run/l2-loop
            runtime_created=1
        fi
        if test -e /run/l2-loop/accept || test -L /run/l2-loop/accept; then
            assert_no_symlink /run/l2-loop/accept
            test -d /run/l2-loop/accept || fail "accept parent is not a directory"
            test "$(stat -c '%u:%g:%a' /run/l2-loop/accept)" = '0:0:700' || fail "accept parent metadata is unsafe"
        else
            mkdir -m 0700 /run/l2-loop/accept
            accept_created=1
        fi
        install -d -m 0700 "$root" "$bundle" "$root/evidence" "$evidence"
        if test "$runtime_created" -eq 1; then install -m 0600 /dev/null "$runtime_marker"; fi
        if test "$accept_created" -eq 1; then install -m 0600 /dev/null "$accept_marker"; fi
        trap - EXIT
        ;;
    verify-bundle)
        cd "$bundle"
        sha256sum --check SHA256SUMS >/dev/null
        python3 - "$commit" <<'PY'
import json, os, stat, sys
expected=sys.argv[1]
names=sorted(os.listdir("."))
required=sorted(["deployment-v1.example.json","l2-loop-deploycheck","l2-loop-ebpf.o","l2-loop-hostcheck","l2-loop-install","l2-loop.service","l2-loopctl","l2-loopd","manifest.json","SHA256SUMS"])
names!=required and sys.exit("remote bundle inventory changed")
with open("manifest.json","r",encoding="utf-8") as channel: manifest=json.load(channel)
(manifest.get("commit_sha")!=expected or manifest.get("files",{}).get("installer")!="l2-loop-install") and sys.exit("remote manifest identity changed")
for name in names:
    item=os.lstat(name)
    (stat.S_ISREG(item.st_mode) and item.st_nlink==1 and item.st_uid==0 and item.st_gid==0) or sys.exit("remote bundle identity changed")
PY
        chmod 0755 l2-loopd l2-loopctl l2-loop-deploycheck l2-loop-hostcheck l2-loop-install
        chmod 0644 l2-loop-ebpf.o l2-loop.service deployment-v1.example.json manifest.json SHA256SUMS
        install -m 0755 "$bundle/l2-loop-hostcheck" "$root/l2-loop-hostcheck"
        install -m 0644 "$bundle/l2-loop-ebpf.o" "$root/l2-loop-ebpf.o"
        ;;
    install-layout) install_layout ;;
    staging-positive) run_checker_positive ;;
    staging-negative) stage_negative ;;
    snapshot) snapshot ;;
    snapshot-prepared) snapshot_prepared ;;
    clock-ms) date +%s%3N ;;
    host-info)
        python3 - "$(uname -m)" "$(uname -r)" "$(nproc)" <<'PY'
import json,sys
print(json.dumps({"architecture":sys.argv[1],"kernel_release":sys.argv[2],"logical_cpu_count":int(sys.argv[3])},sort_keys=True,separators=(",",":")))
PY
        ;;
    resource-counts)
        processes=$(python3 - "$root" <<'PY'
import os,sys
root=sys.argv[1]; count=0
for name in os.listdir("/proc"):
    if name.isdigit():
        try:
            if os.path.realpath("/proc/%s/exe"%name).startswith(root+"/"): count+=1
        except OSError: pass
print(count)
PY
        )
        pin_count=0; test ! -d "$pins" || pin_count=$(find "$pins" -mindepth 1 -maxdepth 1 | wc -l)
        map_count=$pin_count
        program_count=0; test ! -e "$journal" || program_count=2
        namespace_count=0; ! ip netns list | awk '{print $1}' | grep -Fqx -- "$ns" || namespace_count=1
        printf '{"process_count":%s,"map_count":%s,"program_count":%s,"pin_count":%s,"namespace_count":%s}\n' "$processes" "$map_count" "$program_count" "$pin_count" "$namespace_count"
        ;;
    performance-prepare)
        ip netns add "$ns"
        ip link add name "$host" type veth peer name "$peer"
        ip link set dev "$peer" netns "$ns"
        ip link set dev "$host" addrgenmode none
        ip netns exec "$ns" ip link set dev "$peer" addrgenmode none
        ;;
    warm-up)
        ip link set dev "$host" up
        ip netns exec "$ns" ip link set dev "$peer" up
        PER_SIZE=1024
        measure_traffic >/dev/null
        ip link set dev "$host" down
        ip netns exec "$ns" ip link set dev "$peer" down
        ;;
    measure) run_measurement ;;
    cleanup-links)
        if ip link show dev "$host" >/dev/null 2>&1; then ip link delete dev "$host"; fi
        if ip netns list | awk '{print $1}' | grep -Fqx -- "$ns"; then ip netns delete "$ns"; fi
        cleanup_pins
        ;;
    checker-positive) run_checker_positive ;;
    checker-performance-blocked)
        case "$scenario" in
            PerformancePassThroughRegression|PerformanceObserveRegression|PerformanceDropError|PerformanceCleanupMismatch) expected=DG_PERFORMANCE_REGRESSION ;;
            PerformanceIncomplete|PerformanceIdentityMismatch) expected=DG_PERFORMANCE_UNAVAILABLE ;;
            *) fail "unknown performance fixture scenario" ;;
        esac
        run_checker_blocked "$bundle" "$expected"
        ;;
    identity-before-cleanup)
        test -d "$root" && test ! -L "$root" || fail "generated root identity changed before cleanup"
        test "$(stat -c '%u:%g:%a' "$root")" = '0:0:700' || fail "generated root metadata changed before cleanup"
        ;;
    cleanup-generated-tree) cleanup_generated_tree ;;
    postcheck)
        test ! -e "$root" && test ! -L "$root" || fail "generated run root remained after cleanup"
        test ! -e "$journal" && test ! -L "$journal" || fail "generated journal remained after cleanup"
        test ! -e "$pins" && test ! -L "$pins" || fail "generated pin root remained after cleanup"
        ! ip link show dev "$host" >/dev/null 2>&1 || fail "generated host veth remained after cleanup"
        ! ip netns list | awk '{print $1}' | grep -Fqx -- "$ns" || fail "generated namespace remained after cleanup"
        printf '{"generated_residue":0}\n'
        ;;
    *) fail "unknown deployment acceptance phase" ;;
esac
'@

function Invoke-DeploymentRemotePhase {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [string] $Scenario = 'none',
        [switch] $AllowFailure
    )

    Assert-DeploymentCleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot -BundleRoot $Names.BundleRoot -StagingRoot $Names.StagingRoot
    $Arguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @(
        'bash', '-s', '--', $Phase, $Names.RunId, $Names.Namespace, $Names.HostVeth,
        $Names.PeerVeth, $Names.RemoteRunRoot, $Names.BundleRoot, $Names.StagingRoot,
        $Commit, $Scenario
    )
    Invoke-ExactProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $RemoteProgram -TimeoutSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Get-StableDeploymentRemoteState {
    param(
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [ValidateSet('snapshot', 'snapshot-prepared')] [string] $Phase = 'snapshot',
        [ValidateRange(2, 5)] [int] $RequiredConsecutive = 3,
        [ValidateRange(3, 120)] [int] $MaxAttempts = 40,
        [ValidateRange(50, 1000)] [int] $DelayMilliseconds = 250
    )

    $Previous = $null
    $Consecutive = 0
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        $Current = (Invoke-DeploymentRemotePhase -Phase $Phase -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout.Trim()
        $null = $Current | ConvertFrom-Json
        if ($Current -ceq $Previous) { $Consecutive++ } else { $Previous = $Current; $Consecutive = 1 }
        if ($Consecutive -ge $RequiredConsecutive) { return $Current }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    throw 'remote deployment state did not converge within the bounded window'
}

function Wait-DeploymentRemoteState {
    param(
        [Parameter(Mandatory)] [string] $Expected,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [ValidateSet('snapshot', 'snapshot-prepared')] [string] $Phase = 'snapshot',
        [ValidateRange(2, 5)] [int] $RequiredConsecutive = 2,
        [ValidateRange(2, 240)] [int] $MaxAttempts = 120,
        [ValidateRange(50, 1000)] [int] $DelayMilliseconds = 250
    )

    $Matches = 0
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        $Current = (Invoke-DeploymentRemotePhase -Phase $Phase -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout.Trim()
        if ($Current -ceq $Expected) { $Matches++ } else { $Matches = 0 }
        if ($Matches -ge $RequiredConsecutive) { return }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    throw 'remote deployment state was not restored within the bounded window'
}

function Assert-DeploymentRemoteStateUnchanged {
    param(
        [Parameter(Mandatory)] [string] $Before,
        [Parameter(Mandatory)] [string] $After
    )
    if ($Before -cne $After) { throw 'stable network or eBPF identity changed' }
}

function Get-MedianRate {
    param(
        [Parameter(Mandatory)] [object[]] $Trials,
        [Parameter(Mandatory)] [string] $Mode
    )
    # lower-median-of-five; best-run selection is intentionally impossible.
    $Selected = @($Trials | Where-Object { $_.mode -ceq $Mode })
    if ($Selected.Count -ne $PERFORMANCE_TRIAL_COUNT) { throw 'performance trial count is incomplete' }
    $PacketRates = @($Selected.packets_per_second | ForEach-Object { [uint64]$_ } | Sort-Object)
    $ByteRates = @($Selected.bytes_per_second | ForEach-Object { [uint64]$_ } | Sort-Object)
    [pscustomobject]@{
        packets_per_second = [uint64]$PacketRates[2]
        bytes_per_second = [uint64]$ByteRates[2]
    }
}

function Get-ConservativeRatioPermille {
    param(
        [Parameter(Mandatory)] [psobject] $Measured,
        [Parameter(Mandatory)] [psobject] $Baseline
    )
    if ([uint64]$Baseline.packets_per_second -eq 0 -or [uint64]$Baseline.bytes_per_second -eq 0) {
        throw 'baseline rate is zero'
    }
    $PacketRatio = [uint64]([math]::Floor(([double]$Measured.packets_per_second * 1000.0) / [double]$Baseline.packets_per_second))
    $ByteRatio = [uint64]([math]::Floor(([double]$Measured.bytes_per_second * 1000.0) / [double]$Baseline.bytes_per_second))
    [uint16][math]::Min($PacketRatio, $ByteRatio)
}

function Update-PerformanceEvidenceDerivedFields {
    param([Parameter(Mandatory)] [psobject] $Evidence)

    $Trials = @($Evidence.trials)
    $Baseline = Get-MedianRate -Trials $Trials -Mode 'baseline'
    $PassThrough = Get-MedianRate -Trials $Trials -Mode 'pass_through'
    $Observe = Get-MedianRate -Trials $Trials -Mode 'observe'
    $Evidence.medians = [pscustomobject]@{ baseline = $Baseline; pass_through = $PassThrough; observe = $Observe }
    $Evidence.pass_through_baseline_ratio_permille = Get-ConservativeRatioPermille -Measured $PassThrough -Baseline $Baseline
    $Evidence.observe_baseline_ratio_permille = Get-ConservativeRatioPermille -Measured $Observe -Baseline $Baseline
    $TotalCpu = [uint64]0
    $TotalDuration = [uint64]0
    $Peak = [uint64]0
    $Drops = [uint64]0
    $Errors = [uint64]0
    foreach ($Trial in $Trials) {
        $TotalCpu += [uint64]$Trial.daemon_cpu_time_ns
        $TotalDuration += [uint64]$Trial.duration_ns
        $Peak = [math]::Max($Peak, [uint64]$Trial.peak_resident_memory_bytes)
        $Drops += [uint64]$Trial.packet_drop_delta
        $Errors += [uint64]$Trial.packet_error_delta
    }
    $Evidence.daemon_cpu_time_ns = $TotalCpu
    $Evidence.daemon_cpu_permille = [uint16][math]::Floor(([double]$TotalCpu * 1000.0) / [double]$TotalDuration)
    $Evidence.peak_resident_memory_bytes = [uint64]$Peak
    $FirstObserve = @($Trials | Where-Object { $_.trial_number -eq 1 -and $_.mode -ceq 'observe' })[0]
    $FifthObserve = @($Trials | Where-Object { $_.trial_number -eq 5 -and $_.mode -ceq 'observe' })[0]
    $Evidence.rss_growth_bytes = [uint64][math]::Max(0, ([int64]$FifthObserve.peak_resident_memory_bytes - [int64]$FirstObserve.peak_resident_memory_bytes))
    $Evidence.packet_drop_delta = $Drops
    $Evidence.packet_error_delta = $Errors

    $Unavailable = -not $Evidence.warm_up_complete -or -not $Evidence.measurement_complete -or $Evidence.measurement_noisy -or -not $Evidence.host_identity_stable
    $Regression = [uint16]$Evidence.pass_through_baseline_ratio_permille -lt $PERFORMANCE_PASS_THROUGH_MIN_PERMILLE -or
        [uint16]$Evidence.observe_baseline_ratio_permille -lt $PERFORMANCE_OBSERVE_MIN_PERMILLE -or
        [uint16]$Evidence.daemon_cpu_permille -gt $PERFORMANCE_MAX_CPU_PERMILLE -or
        [uint64]$Evidence.peak_resident_memory_bytes -gt $PERFORMANCE_MAX_RSS_BYTES -or
        [uint64]$Evidence.rss_growth_bytes -gt $PERFORMANCE_MAX_RSS_GROWTH_BYTES -or
        $Drops -ne 0 -or $Errors -ne 0 -or
        [uint32]$Evidence.process_count_before -ne [uint32]$Evidence.process_count_after -or
        [uint32]$Evidence.map_count_before -ne [uint32]$Evidence.map_count_after -or
        [uint32]$Evidence.program_count_before -ne [uint32]$Evidence.program_count_after -or
        [uint32]$Evidence.pin_count_before -ne [uint32]$Evidence.pin_count_after -or
        [uint32]$Evidence.namespace_count_before -ne [uint32]$Evidence.namespace_count_after -or
        -not $Evidence.forwarding_intact -or -not $Evidence.owned_cleanup_complete -or
        -not $Evidence.network_identity_restored -or -not $Evidence.ebpf_identity_restored
    if ($Unavailable) {
        $Evidence.result = 'unavailable'
        $Evidence.findings = @('DG_PERFORMANCE_UNAVAILABLE')
    }
    elseif ($Regression) {
        $Evidence.result = 'failed'
        $Evidence.findings = @('DG_PERFORMANCE_REGRESSION')
    }
    else {
        $Evidence.result = 'passed'
        $Evidence.findings = @()
    }
    $Evidence
}

function New-PerformanceEvidence {
    param(
        [Parameter(Mandatory)] [object[]] $Trials,
        [Parameter(Mandatory)] [psobject] $HostInfo,
        [Parameter(Mandatory)] [psobject] $ResourceBefore,
        [Parameter(Mandatory)] [psobject] $ResourceAfter,
        [Parameter(Mandatory)] [string] $PackageVersion,
        [Parameter(Mandatory)] [string] $EvidenceId,
        [Parameter(Mandatory)] [uint64] $IssuedAt,
        [Parameter(Mandatory)] [bool] $IdentityRestored
    )

    $Forwarding = @($Trials | Where-Object { -not $_.forwarding_intact }).Count -eq 0
    foreach ($Trial in $Trials) { $Trial.PSObject.Properties.Remove('forwarding_intact') }
    $Evidence = [pscustomobject]@{
        schema_version = 1
        evidence_id = $EvidenceId
        artifact_commit_sha = $Commit
        package_version = $PackageVersion
        architecture = [string]$HostInfo.architecture
        kernel_release = [string]$HostInfo.kernel_release
        logical_cpu_count = [uint32]$HostInfo.logical_cpu_count
        veth_xdp_mode = 'generic'
        issued_at_unix_ms = $IssuedAt
        expires_at_unix_ms = $IssuedAt + 3600000
        warm_up_complete = $true
        measurement_complete = $true
        measurement_noisy = $false
        host_identity_stable = $IdentityRestored
        trials = $Trials
        medians = $null
        pass_through_baseline_ratio_permille = 0
        observe_baseline_ratio_permille = 0
        daemon_cpu_time_ns = 0
        daemon_cpu_permille = 0
        peak_resident_memory_bytes = 0
        rss_growth_bytes = 0
        packet_drop_delta = 0
        packet_error_delta = 0
        process_count_before = [uint32]$ResourceBefore.process_count
        process_count_after = [uint32]$ResourceAfter.process_count
        map_count_before = [uint32]$ResourceBefore.map_count
        map_count_after = [uint32]$ResourceAfter.map_count
        program_count_before = [uint32]$ResourceBefore.program_count
        program_count_after = [uint32]$ResourceAfter.program_count
        pin_count_before = [uint32]$ResourceBefore.pin_count
        pin_count_after = [uint32]$ResourceAfter.pin_count
        namespace_count_before = [uint32]$ResourceBefore.namespace_count
        namespace_count_after = [uint32]$ResourceAfter.namespace_count
        forwarding_intact = $Forwarding
        owned_cleanup_complete = $true
        network_identity_restored = $IdentityRestored
        ebpf_identity_restored = $IdentityRestored
        result = 'unavailable'
        findings = @('DG_PERFORMANCE_UNAVAILABLE')
    }

    foreach ($Mode in @('baseline', 'pass_through', 'observe')) {
        $Rates = @($Trials | Where-Object { $_.mode -ceq $Mode } | ForEach-Object { [uint64]$_.packets_per_second } | Sort-Object)
        if ($Rates.Count -ne 5 -or [uint64]$Rates[0] -eq 0 -or ([uint64]$Rates[4] * 1000) / [uint64]$Rates[0] -gt 1250) {
            $Evidence.measurement_noisy = $true
        }
    }
    Update-PerformanceEvidenceDerivedFields -Evidence $Evidence
}

function Write-StrictJsonFile {
    param(
        [Parameter(Mandatory)] [psobject] $Value,
        [Parameter(Mandatory)] [string] $Path
    )
    $Json = $Value | ConvertTo-Json -Depth 20 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($Json) -gt $MAX_OUTPUT_BYTES) { throw 'strict evidence JSON exceeded the bound' }
    [IO.File]::WriteAllText($Path, $Json, [Text.UTF8Encoding]::new($false))
}

function Send-GeneratedFile {
    param(
        [Parameter(Mandatory)] [string] $LocalPath,
        [Parameter(Mandatory)] [string] $RemotePath,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )
    $Arguments = Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources @($LocalPath) -Destination $RemotePath
    $null = Invoke-ExactProcess -FilePath 'scp' -ArgumentList $Arguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
}

function New-PerformanceFailureFixture {
    param(
        [Parameter(Mandatory)] [psobject] $Evidence,
        [Parameter(Mandatory)] [string] $Scenario
    )
    $Copy = ($Evidence | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json
    switch ($Scenario) {
        'PerformancePassThroughRegression' {
            foreach ($Trial in @($Copy.trials | Where-Object { $_.mode -ceq 'pass_through' })) {
                $Trial.duration_ns = [uint64]$Trial.duration_ns * 2
                $Trial.packets_per_second = [uint64][math]::Floor((196608.0 * 1000000000.0) / [double]$Trial.duration_ns)
                $Trial.bytes_per_second = [uint64][math]::Floor((136970240.0 * 1000000000.0) / [double]$Trial.duration_ns)
            }
        }
        'PerformanceObserveRegression' {
            foreach ($Trial in @($Copy.trials | Where-Object { $_.mode -ceq 'observe' })) {
                $Trial.duration_ns = [uint64]$Trial.duration_ns * 2
                $Trial.packets_per_second = [uint64][math]::Floor((196608.0 * 1000000000.0) / [double]$Trial.duration_ns)
                $Trial.bytes_per_second = [uint64][math]::Floor((136970240.0 * 1000000000.0) / [double]$Trial.duration_ns)
            }
        }
        'PerformanceDropError' { $Copy.trials[0].packet_drop_delta = 1 }
        'PerformanceIncomplete' { $Copy.measurement_complete = $false }
        'PerformanceIdentityMismatch' { $Copy.artifact_commit_sha = '0000000000000000000000000000000000000000' }
        'PerformanceCleanupMismatch' { $Copy.owned_cleanup_complete = $false }
        default { throw 'unknown performance failure fixture' }
    }
    Update-PerformanceEvidenceDerivedFields -Evidence $Copy
}

function Register-DeploymentCleanup {
    param([Parameter(Mandatory)] [scriptblock] $Action)
    $script:DeploymentCleanupAction = $Action
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($null -ne $script:DeploymentCleanupAction) { & $script:DeploymentCleanupAction }
    }
}

$Target = [Environment]::GetEnvironmentVariable('L2_LOOP_TEST_TARGET')
$KeyPath = [Environment]::GetEnvironmentVariable('L2_LOOP_TEST_KEY')
if ([string]::IsNullOrWhiteSpace($Target) -or [string]::IsNullOrWhiteSpace($KeyPath)) {
    throw 'L2_LOOP_TEST_TARGET and L2_LOOP_TEST_KEY are mandatory task-scoped inputs'
}
$KeyItem = Get-Item -LiteralPath $KeyPath
Assert-NoSymlink -Item $KeyItem

$Artifact = Get-ExactGreenDeploymentBundle -Commit $Commit
$RunId = New-CryptographicRunId
$EvidenceId = New-CryptographicRunId
$Names = New-DeploymentGateNames -RunId $RunId
Assert-DeploymentCleanupTarget -Names $Names -Namespace $Names.Namespace -HostVeth $Names.HostVeth -PeerVeth $Names.PeerVeth -RunRoot $Names.RemoteRunRoot -BundleRoot $Names.BundleRoot -StagingRoot $Names.StagingRoot
$LocalEvidencePath = Join-Path $RepositoryRoot ".artifacts/performance-$RunId.json"

$script:DeploymentCleanupComplete = $false
$script:CleanupFinalState = $null
$script:DeploymentMutationStarted = $false
$CleanupAction = {
    if (-not $script:DeploymentCleanupComplete) {
        if (-not $script:DeploymentMutationStarted) {
            $script:DeploymentCleanupComplete = $true
            return
        }
        $Identity = Invoke-DeploymentRemotePhase -Phase 'identity-before-cleanup' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -AllowFailure
        if ($Identity.ExitCode -ne 0) { throw "identity-before-cleanup failed: $($Identity.Stderr.Trim())" }
        $Result = Invoke-DeploymentRemotePhase -Phase 'cleanup-generated-tree' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -AllowFailure
        if ($Result.ExitCode -ne 0) { throw "cleanup-generated-tree failed: $($Result.Stderr.Trim())" }
        $script:CleanupFinalState = $Result.Stdout.Trim()
        $script:DeploymentCleanupComplete = $true
    }
}
$ExitEvent = Register-DeploymentCleanup -Action $CleanupAction
$CancelHandler = [ConsoleCancelEventHandler]{
    param($Sender, $EventArgs)
    $EventArgs.Cancel = $true
    if ($null -ne $script:DeploymentCleanupAction) { & $script:DeploymentCleanupAction }
}
[Console]::add_CancelKeyPress($CancelHandler)

try {
    $null = Invoke-DeploymentRemotePhase -Phase 'precheck' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $script:DeploymentMutationStarted = $true
    $null = Invoke-DeploymentRemotePhase -Phase 'create-root' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $Sources = $ExpectedBundleFiles | ForEach-Object { Join-Path $Artifact.Root $_ }
    $ScpArguments = Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources $Sources -Destination "$($Names.BundleRoot)/"
    $null = Invoke-ExactProcess -FilePath 'scp' -ArgumentList $ScpArguments -StandardInput $null -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-DeploymentRemotePhase -Phase 'verify-bundle' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $BeforeState = Get-StableDeploymentRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $ResourceBefore = (Invoke-DeploymentRemotePhase -Phase 'resource-counts' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout | ConvertFrom-Json

    $null = Invoke-DeploymentRemotePhase -Phase 'install-layout' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-DeploymentRemotePhase -Phase 'staging-positive' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    foreach ($Scenario in $STAGING_SCENARIOS | Where-Object { $_ -cne 'Positive' }) {
        Write-Host "staging scenario: $Scenario"
        $null = Invoke-DeploymentRemotePhase -Phase 'staging-negative' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Scenario $Scenario
        $null = Invoke-DeploymentRemotePhase -Phase 'staging-positive' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    }

    $HostInfo = (Invoke-DeploymentRemotePhase -Phase 'host-info' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout | ConvertFrom-Json
    $null = Invoke-DeploymentRemotePhase -Phase 'performance-prepare' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $PreparedState = Get-StableDeploymentRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Phase 'snapshot-prepared'
    $null = Invoke-DeploymentRemotePhase -Phase 'warm-up' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Scenario 'warm-up'
    Wait-DeploymentRemoteState -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Phase 'snapshot-prepared'

    $Trials = [Collections.Generic.List[object]]::new()
    for ($TrialNumber = 1; $TrialNumber -le $PERFORMANCE_TRIAL_COUNT; $TrialNumber++) {
        foreach ($Mode in $PERFORMANCE_TRIAL_ORDERS[$TrialNumber - 1]) {
            Write-Host "performance trial $TrialNumber mode: $Mode"
            $Measurement = (Invoke-DeploymentRemotePhase -Phase 'measure' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Scenario $Mode).Stdout | ConvertFrom-Json
            $Trial = [ordered]@{
                trial_number = [byte]$TrialNumber
                mode = $Mode
                frame_sizes = $PERFORMANCE_FRAME_SIZES
                frames_per_size = [uint32]$PERFORMANCE_FRAMES_PER_SIZE
                duration_ns = [uint64]$Measurement.duration_ns
                packets_per_second = [uint64]$Measurement.packets_per_second
                bytes_per_second = [uint64]$Measurement.bytes_per_second
                daemon_cpu_time_ns = [uint64]$Measurement.daemon_cpu_time_ns
                peak_resident_memory_bytes = [uint64]$Measurement.peak_resident_memory_bytes
                packet_drop_delta = [uint64]$Measurement.packet_drop_delta
                packet_error_delta = [uint64]$Measurement.packet_error_delta
                forwarding_intact = [bool]$Measurement.forwarding_intact
            }
            $Trials.Add([pscustomobject]$Trial)
            Wait-DeploymentRemoteState -Expected $PreparedState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Phase 'snapshot-prepared'
        }
    }

    $null = Invoke-DeploymentRemotePhase -Phase 'cleanup-links' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    Wait-DeploymentRemoteState -Expected $BeforeState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $AfterState = Get-StableDeploymentRemoteState -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    Assert-DeploymentRemoteStateUnchanged -Before $BeforeState -After $AfterState
    $ResourceAfter = (Invoke-DeploymentRemotePhase -Phase 'resource-counts' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout | ConvertFrom-Json
    $IssuedAtText = (Invoke-DeploymentRemotePhase -Phase 'clock-ms' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout.Trim()
    if ($IssuedAtText -cnotmatch '^[0-9]{13}$') { throw 'remote evidence clock is invalid' }
    $IssuedAt = [uint64]$IssuedAtText
    $Evidence = New-PerformanceEvidence -Trials $Trials.ToArray() -HostInfo $HostInfo -ResourceBefore $ResourceBefore -ResourceAfter $ResourceAfter -PackageVersion $Artifact.PackageVersion -EvidenceId $EvidenceId -IssuedAt $IssuedAt -IdentityRestored $true
    Write-Host "performance result: $($Evidence.result) pass-through=$($Evidence.pass_through_baseline_ratio_permille) observe=$($Evidence.observe_baseline_ratio_permille) cpu=$($Evidence.daemon_cpu_permille) drops=$($Evidence.packet_drop_delta) errors=$($Evidence.packet_error_delta) noisy=$($Evidence.measurement_noisy)"
    Write-StrictJsonFile -Value $Evidence -Path $LocalEvidencePath
    Send-GeneratedFile -LocalPath $LocalEvidencePath -RemotePath $Names.PerformancePath -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-DeploymentRemotePhase -Phase 'checker-positive' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds

    foreach ($Scenario in $PERFORMANCE_FAILURE_SCENARIOS) {
        $Fixture = New-PerformanceFailureFixture -Evidence $Evidence -Scenario $Scenario
        Write-StrictJsonFile -Value $Fixture -Path $LocalEvidencePath
        Send-GeneratedFile -LocalPath $LocalEvidencePath -RemotePath $Names.PerformancePath -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
        $null = Invoke-DeploymentRemotePhase -Phase 'checker-performance-blocked' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds -Scenario $Scenario
    }
    Write-StrictJsonFile -Value $Evidence -Path $LocalEvidencePath
    Send-GeneratedFile -LocalPath $LocalEvidencePath -RemotePath $Names.PerformancePath -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds
    $null = Invoke-DeploymentRemotePhase -Phase 'checker-positive' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds

    & $CleanupAction
    Assert-DeploymentRemoteStateUnchanged -Before $BeforeState -After $script:CleanupFinalState
    $Postcheck = (Invoke-DeploymentRemotePhase -Phase 'postcheck' -Names $Names -Target $Target -KeyPath $KeyPath -TimeoutSeconds $TimeoutSeconds).Stdout | ConvertFrom-Json
    if ([uint32]$Postcheck.generated_residue -ne 0) { throw 'generated residue remained after cleanup' }
    [pscustomobject]@{
        commit_sha = $Commit
        artifact_run_id = $Artifact.RunId
        run_id = $RunId
        staging_scenarios = $STAGING_SCENARIOS.Count
        performance_failure_scenarios = $PERFORMANCE_FAILURE_SCENARIOS.Count
        performance_trials = $Trials.Count
        medians = $Evidence.medians
        pass_through_baseline_ratio_permille = $Evidence.pass_through_baseline_ratio_permille
        observe_baseline_ratio_permille = $Evidence.observe_baseline_ratio_permille
        result = $Evidence.result
        network_identity_restored = $true
        ebpf_identity_restored = $true
        generated_residue = 0
    } | ConvertTo-Json -Depth 8
}
finally {
    try {
        if (-not $script:DeploymentCleanupComplete) { & $CleanupAction }
    }
    finally {
        [Console]::remove_CancelKeyPress($CancelHandler)
        if ($null -ne $ExitEvent) { Unregister-Event -SourceIdentifier PowerShell.Exiting -ErrorAction SilentlyContinue }
        $script:DeploymentCleanupAction = $null
        if (Test-Path -LiteralPath $LocalEvidencePath) { [IO.File]::Delete($LocalEvidencePath) }
    }
}
