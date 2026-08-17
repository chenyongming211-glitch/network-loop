[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,

    [Parameter(Mandatory)] [string] $InstallAuthorizationPath,
    [Parameter(Mandatory)] [string] $RollbackAuthorizationPath,
    [Parameter(Mandatory)] [string] $ServiceAuthorizationPath,
    [Parameter(Mandatory)] [string] $DeploymentAuthorizationPath,
    [Parameter(Mandatory)] [string] $PerformanceEvidencePath,

    [ValidateRange(120, 1800)]
    [int] $TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$MAX_OUTPUT_BYTES = 1048576
$EXPECTED_BUNDLE_FILE_COUNT = 10
$EXPECTED_CHECKSUM_COUNT = 9
$ExpectedBundleFiles = @(
    'SHA256SUMS', 'deployment-v1.example.json', 'l2-loop-deploycheck',
    'l2-loop-ebpf.o', 'l2-loop-hostcheck', 'l2-loop-install',
    'l2-loop.service', 'l2-loopctl', 'l2-loopd', 'manifest.json'
)
$ExecutableBundleFiles = @('l2-loop-deploycheck', 'l2-loop-hostcheck', 'l2-loop-install', 'l2-loopctl', 'l2-loopd')
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ServiceHarness = Join-Path $PSScriptRoot 'verify-installed-service.ps1'
Import-Module (Join-Path $PSScriptRoot 'lib/IsolatedNames.psm1')

$script:RealInstallCleanupAction = $null
$script:RealInstallCleanupComplete = $false

function Invoke-ExactInstallProcess {
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

function New-InstallRunId {
    $Bytes = [byte[]]::new(16)
    $Generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $Generator.GetBytes($Bytes) } finally { $Generator.Dispose() }
    -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-RequiredInstallEnvironment {
    param([string] $Name)
    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Name must be set explicitly" }
    $Value
}

function Assert-NoLocalLink {
    param([Parameter(Mandatory)] [IO.FileSystemInfo] $Item)
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'local input links are refused' }
}

function Get-ExactGreenInstallBundle {
    param([Parameter(Mandatory)] [string] $ArtifactCommit)
    $Query = Invoke-ExactInstallProcess -FilePath 'gh' -ArgumentList @(
        'run', 'list', '--branch', 'main', '--commit', $ArtifactCommit, '--limit', '10',
        '--json', 'databaseId,conclusion,headSha'
    ) -StandardInput $null -BoundSeconds 60
    $Run = @($Query.Stdout | ConvertFrom-Json) |
        Where-Object { $null -ne $_ -and $_.headSha -ceq $ArtifactCommit -and $_.conclusion -ceq 'success' } |
        Select-Object -First 1
    if ($null -eq $Run) { throw 'exact commit has no successful GitHub Actions run' }
    $ArtifactRoot = Join-Path $RepositoryRoot ".artifacts/real-install-$ArtifactCommit"
    if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
        $null = Invoke-ExactInstallProcess -FilePath 'gh' -ArgumentList @(
            'run', 'download', [string]$Run.databaseId,
            '--name', "l2-loop-linux-x86_64-$ArtifactCommit", '--dir', $ArtifactRoot
        ) -StandardInput $null -BoundSeconds 180
    }
    [pscustomobject]@{ Root = (Resolve-Path -LiteralPath $ArtifactRoot).Path; WorkflowRunId = [uint64]$Run.databaseId }
}

function Assert-ExactBundle {
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $ArtifactCommit)
    $RootItem = Get-Item -LiteralPath $Root
    Assert-NoLocalLink -Item $RootItem
    $Items = @([IO.Directory]::EnumerateFileSystemEntries($Root) | ForEach-Object { Get-Item -LiteralPath $_ })
    if ($Items.Count -ne $EXPECTED_BUNDLE_FILE_COUNT -or @($Items | Where-Object { $_.PSIsContainer }).Count -ne 0 -or
        (@($Items.Name | Sort-Object) -join ',') -cne (@($ExpectedBundleFiles | Sort-Object) -join ',')) {
        throw 'bundle inventory is not exact'
    }
    foreach ($Item in $Items) { Assert-NoLocalLink -Item $Item }
    $ChecksumLines = @(Get-Content -LiteralPath (Join-Path $Root 'SHA256SUMS'))
    if ($ChecksumLines.Count -ne $EXPECTED_CHECKSUM_COUNT) { throw 'checksum count is not exact' }
    $Covered = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($Line in $ChecksumLines) {
        if ($Line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') { throw 'checksum line is not canonical' }
        $Hash = $Matches[1]; $Name = $Matches[2]
        if ($Name -ceq 'SHA256SUMS' -or $Name -cnotin $ExpectedBundleFiles -or -not $Covered.Add($Name)) { throw 'checksum coverage is invalid' }
        $Actual = (Get-FileHash -LiteralPath (Join-Path $Root $Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Actual -cne $Hash) { throw "checksum mismatch for $Name" }
    }
    $Manifest = Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw | ConvertFrom-Json
    if ([string]$Manifest.commit_sha -cne $ArtifactCommit -or
        [string]$Manifest.files.installer -cne 'l2-loop-install' -or
        [string]$Manifest.files.deployment_checker -cne 'l2-loop-deploycheck') {
        throw 'manifest identity does not match the exact artifact'
    }
    [pscustomobject]@{
        Manifest = $Manifest
        ManifestSha256 = (Get-FileHash -LiteralPath (Join-Path $Root 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Assert-StrictInstallAuthorization {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [ValidateSet('install', 'rollback')] [string] $Operation,
        [Parameter(Mandatory)] [string] $ArtifactCommit,
        [Parameter(Mandatory)] [string] $ManifestSha256,
        [Parameter(Mandatory)] [string] $HostIdentity,
        [Parameter(Mandatory)] [string] $DeploymentSha256,
        [Parameter(Mandatory)] [string] $PerformanceSha256
    )
    $Item = Get-Item -LiteralPath $Path
    Assert-NoLocalLink -Item $Item
    if ($Item.PSIsContainer -or $Item.Length -gt 16384) { throw 'install authorization must be one bounded regular file' }
    $Value = Get-Content -LiteralPath $Item.FullName -Raw | ConvertFrom-Json
    $Fields = @('artifact_commit_sha','authorization_id','bundle_manifest_sha256','deployment_authorization_sha256','expires_at_unix_ms','host_identity_sha256','issued_at_unix_ms','operation','performance_evidence_sha256','physical_attach','schema_version','service_enable','service_start','transaction_id') | Sort-Object
    if ((@($Value.PSObject.Properties.Name | Sort-Object) -join ',') -cne ($Fields -join ',')) { throw 'install authorization schema is not exact' }
    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    if ([int]$Value.schema_version -ne 1 -or [string]$Value.operation -cne $Operation -or
        [string]$Value.authorization_id -cnotmatch '^[0-9a-f]{32}$' -or [string]$Value.transaction_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Value.artifact_commit_sha -cne $ArtifactCommit -or [string]$Value.bundle_manifest_sha256 -cne $ManifestSha256 -or
        [string]$Value.host_identity_sha256 -cne $HostIdentity -or
        [string]$Value.deployment_authorization_sha256 -cne $DeploymentSha256 -or
        [string]$Value.performance_evidence_sha256 -cne $PerformanceSha256 -or
        [int64]$Value.issued_at_unix_ms -gt $Now -or [int64]$Value.expires_at_unix_ms -le $Now -or
        ([int64]$Value.expires_at_unix_ms - [int64]$Value.issued_at_unix_ms) -gt 3600000 -or
        [bool]$Value.service_enable -or [bool]$Value.service_start -or [bool]$Value.physical_attach) {
        throw 'install authorization binding or safety flags are invalid'
    }
    $Value
}

function Register-RealInstallCleanup {
    param([Parameter(Mandatory)] [scriptblock] $Action)
    $script:RealInstallCleanupAction = $Action
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($null -ne $script:RealInstallCleanupAction -and -not $script:RealInstallCleanupComplete) { & $script:RealInstallCleanupAction }
    }
}

function Unregister-RealInstallCleanup {
    param([Parameter(Mandatory)] [ConsoleCancelEventHandler] $CancelHandler)
    [Console]::remove_CancelKeyPress($CancelHandler)
    Unregister-Event -SourceIdentifier PowerShell.Exiting -ErrorAction SilentlyContinue
    $script:RealInstallCleanupAction = $null
}

$RemoteInstallProgram = @'
set -Eeuo pipefail
phase=$1
run=$2
root=$3
commit=$4
transaction=$5
nonce=$6
trap 'code=$?; printf "install phase failed: phase=%s line=%s code=%s\n" "$phase" "$LINENO" "$code" >&2; exit "$code"' ERR
bundle="$root/bundle"
inputs="$root/inputs"
fail() { printf '%s\n' "$1" >&2; exit 1; }
assert_generated() {
    case "$run" in *[!0-9a-f]*|'') fail 'invalid generated run' ;; esac
    test "${#run}" -eq 32 || fail 'invalid generated run length'
    test "$root" = "/run/l2-loop/accept/$run" || fail 'invalid generated install root'
    case "$transaction" in *[!0-9a-f]*|'') fail 'invalid transaction' ;; esac
    test "${#transaction}" -eq 32 || fail 'invalid transaction length'
    case "$nonce" in *[!0-9a-f]*|'') fail 'invalid controller ownership nonce' ;; esac
    test "${#nonce}" -eq 32 || fail 'invalid controller ownership nonce length'
}
assert_owned() {
    test -f "$root/ownership" && test ! -L "$root/ownership" || fail 'install ownership marker is unavailable'
    test "$(cat -- "$root/ownership")" = "$nonce" || fail 'install ownership marker changed'
}
snapshot() {
    python3 <<'PY'
import hashlib,json,subprocess
def get(argv):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    if len(p.stdout)>1048576: raise SystemExit('snapshot output bound exceeded')
    return p.stdout
n=get(['ip','-j','link','show'])+b'\0'+get(['ip','netns','list'])
b=b'\0'.join(get(x) for x in (['bpftool','-j','prog','show'],['bpftool','-j','map','show'],['bpftool','-j','link','show']))
print(json.dumps({'network':hashlib.sha256(n).hexdigest(),'ebpf':hashlib.sha256(b).hexdigest()},separators=(',',':')))
PY
}
cleanup_generated() {
    assert_owned
    if test -d "$root"; then
        test ! -L "$root" || fail 'generated root became a link'
        for leaf in install.json rollback.json service.json deployment.json performance.json; do test ! -e "$inputs/$leaf" || unlink -- "$inputs/$leaf"; done
        test ! -d "$inputs" || rmdir -- "$inputs"
        for leaf in SHA256SUMS deployment-v1.example.json l2-loop-deploycheck l2-loop-ebpf.o l2-loop-hostcheck l2-loop-install l2-loop.service l2-loopctl l2-loopd manifest.json; do test ! -e "$bundle/$leaf" || unlink -- "$bundle/$leaf"; done
        test ! -d "$bundle" || rmdir -- "$bundle"
        unlink -- "$root/ownership"
        rmdir -- "$root"
    fi
}
assert_generated
case "$phase" in precheck|residue) ;; *) assert_owned ;; esac
case "$phase" in
precheck)
    test "$(id -u)" -eq 0 || fail 'real installation acceptance requires root'
    for name in ip bpftool python3 sha256sum install chmod unlink rmdir mkdir; do command -v "$name" >/dev/null || fail 'required command unavailable'; done
    test ! -e "$root" || fail 'generated install root occupied'
    install -d -m 0700 -- "$root" "$bundle" "$inputs"
    printf '%s\n' "$nonce" >"$root/ownership"
    chmod 0600 -- "$root/ownership"
    ;;
verify-bundle)
    test "$(find "$bundle" -mindepth 1 -maxdepth 1 -type f -printf x | wc -c)" -eq 10 || fail 'remote bundle count mismatch'
    (cd "$bundle" && sha256sum -c SHA256SUMS >/dev/null)
    test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["commit_sha"])' "$bundle/manifest.json")" = "$commit" || fail 'remote manifest commit mismatch'
    chmod 0755 -- "$bundle/l2-loop-deploycheck" "$bundle/l2-loop-hostcheck" "$bundle/l2-loop-install" "$bundle/l2-loopctl" "$bundle/l2-loopd"
    chmod 0644 -- "$bundle/SHA256SUMS" "$bundle/deployment-v1.example.json" "$bundle/l2-loop-ebpf.o" "$bundle/l2-loop.service" "$bundle/manifest.json"
    ;;
snapshot) snapshot ;;
plan)
    "$bundle/l2-loop-install" plan --bundle "$bundle" --authorization "$inputs/install.json" --deployment-authorization "$inputs/deployment.json" --performance-evidence "$inputs/performance.json" --json
    ;;
apply)
    "$bundle/l2-loop-install" apply --bundle "$bundle" --authorization "$inputs/install.json" --deployment-authorization "$inputs/deployment.json" --performance-evidence "$inputs/performance.json" --json
    ;;
installed)
    /usr/libexec/l2-loop/l2-loop-deploycheck installed --json
    ;;
rollback)
    /usr/libexec/l2-loop/l2-loop-install rollback --transaction "$transaction" --authorization "$inputs/rollback.json" --json
    ;;
cleanup) cleanup_generated ;;
residue) if test -e "$root"; then printf '1\n'; else printf '0\n'; fi ;;
*) fail 'unknown real installation phase' ;;
esac
'@

function Invoke-RemoteInstallPhase {
    param(
        [Parameter(Mandatory)] [string] $Phase,
        [Parameter(Mandatory)] [psobject] $Names,
        [Parameter(Mandatory)] [string] $TransactionId,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [string] $KeyPath,
        [switch] $AllowFailure
    )
    Assert-IsolatedRunId -RunId $Names.RunId
    if ($Names.RemoteRunRoot -cne "/run/l2-loop/accept/$($Names.RunId)") { throw 'real install generated root identity mismatch' }
    $Arguments = Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @('bash','-s','--',$Phase,$Names.RunId,$Names.RemoteRunRoot,$Commit,$TransactionId,$Names.ControllerOwnershipNonce)
    Invoke-ExactInstallProcess -FilePath 'ssh' -ArgumentList $Arguments -StandardInput $RemoteInstallProgram -BoundSeconds $TimeoutSeconds -AllowFailure:$AllowFailure
}

function Get-StableRealInstallState {
    param([psobject] $Names, [string] $TransactionId, [string] $Target, [string] $KeyPath)
    $Previous = $null
    for ($Attempt = 0; $Attempt -lt 12; $Attempt++) {
        $Current = (Invoke-RemoteInstallPhase -Phase 'snapshot' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath).Stdout.Trim() | ConvertFrom-Json
        $Canonical = $Current | ConvertTo-Json -Compress
        if ($Canonical -ceq $Previous) { return $Current }
        $Previous = $Canonical
        Start-Sleep -Milliseconds 250
    }
    throw 'real install host state did not converge'
}

function Assert-RealInstallStateUnchanged {
    param([psobject] $Before, [psobject] $After)
    if ($Before.network -cne $After.network -or $Before.ebpf -cne $After.ebpf) { throw 'network or eBPF identity changed across real installation acceptance' }
}

function Assert-InstallDecision {
    param([Parameter(Mandatory)] [psobject] $Result, [Parameter(Mandatory)] [string] $Expected)
    if ($Result.ExitCode -ne 0) { throw "installation phase returned $($Result.ExitCode)" }
    $Report = $Result.Stdout | ConvertFrom-Json
    if ([string]$Report.decision -cne $Expected) { throw "expected decision $Expected" }
    $Report
}

function Invoke-RealInstallCleanup {
    param([psobject] $Names, [string] $TransactionId, [string] $Target, [string] $KeyPath)
    $null = Invoke-RemoteInstallPhase -Phase 'cleanup' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath -AllowFailure
}

$Target = Get-RequiredInstallEnvironment -Name 'L2_LOOP_TEST_TARGET'
$KeyPath = Get-RequiredInstallEnvironment -Name 'L2_LOOP_TEST_KEY'
$Bundle = Get-ExactGreenInstallBundle -ArtifactCommit $Commit
$BundleIdentity = Assert-ExactBundle -Root $Bundle.Root -ArtifactCommit $Commit
$DeploymentSha256 = (Get-FileHash -LiteralPath $DeploymentAuthorizationPath -Algorithm SHA256).Hash.ToLowerInvariant()
$PerformanceSha256 = (Get-FileHash -LiteralPath $PerformanceEvidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
$HostIdentity = (Invoke-ExactInstallProcess -FilePath 'ssh' -ArgumentList (Get-SshArguments -Target $Target -KeyPath $KeyPath -RemoteArguments @('sha256sum','/etc/machine-id')) -StandardInput $null -BoundSeconds 30).Stdout.Split(' ')[0].Trim()
$InstallAuthorization = Assert-StrictInstallAuthorization -Path $InstallAuthorizationPath -Operation 'install' -ArtifactCommit $Commit -ManifestSha256 $BundleIdentity.ManifestSha256 -HostIdentity $HostIdentity -DeploymentSha256 $DeploymentSha256 -PerformanceSha256 $PerformanceSha256
$RollbackAuthorization = Assert-StrictInstallAuthorization -Path $RollbackAuthorizationPath -Operation 'rollback' -ArtifactCommit $Commit -ManifestSha256 $BundleIdentity.ManifestSha256 -HostIdentity $HostIdentity -DeploymentSha256 $DeploymentSha256 -PerformanceSha256 $PerformanceSha256
if ([string]$InstallAuthorization.transaction_id -cne [string]$RollbackAuthorization.transaction_id) { throw 'install and rollback authorizations bind different transactions' }
$TransactionId = [string]$InstallAuthorization.transaction_id
$Names = New-IsolatedNames -RunId (New-InstallRunId)
$Names | Add-Member -NotePropertyName ControllerOwnershipNonce -NotePropertyValue (New-InstallRunId)
$ServiceRunId = New-InstallRunId

$CleanupAction = { Invoke-RealInstallCleanup -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath }
Register-RealInstallCleanup -Action $CleanupAction
$CancelHandler = [ConsoleCancelEventHandler]{
    param($Sender, $EventArgs)
    $EventArgs.Cancel = $true
    if ($null -ne $script:RealInstallCleanupAction -and -not $script:RealInstallCleanupComplete) { & $script:RealInstallCleanupAction }
}
[Console]::add_CancelKeyPress($CancelHandler)

try {
    $null = Invoke-RemoteInstallPhase -Phase 'precheck' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $Sources = @($ExpectedBundleFiles | ForEach-Object { Join-Path $Bundle.Root $_ })
    $null = Invoke-ExactInstallProcess -FilePath 'scp' -ArgumentList (Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources $Sources -Destination "$($Names.RemoteRunRoot)/bundle/") -StandardInput $null -BoundSeconds 180
    $InputSources = @($InstallAuthorizationPath, $RollbackAuthorizationPath, $ServiceAuthorizationPath, $DeploymentAuthorizationPath, $PerformanceEvidencePath) | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
    $InputNames = @('install.json','rollback.json','service.json','deployment.json','performance.json')
    for ($Index = 0; $Index -lt $InputSources.Count; $Index++) {
        $null = Invoke-ExactInstallProcess -FilePath 'scp' -ArgumentList (Get-ScpArguments -Target $Target -KeyPath $KeyPath -Sources @($InputSources[$Index]) -Destination "$($Names.RemoteRunRoot)/inputs/$($InputNames[$Index])") -StandardInput $null -BoundSeconds 60
    }
    $null = Invoke-RemoteInstallPhase -Phase 'verify-bundle' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $BeforeState = Get-StableRealInstallState -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath

    $PlanResult = Invoke-RemoteInstallPhase -Phase 'plan' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $PlanReport = Assert-InstallDecision -Result $PlanResult -Expected 'install_plan_ready'
    $ApplyResult = Invoke-RemoteInstallPhase -Phase 'apply' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $ApplyReport = Assert-InstallDecision -Result $ApplyResult -Expected 'installed_verified'
    $InstalledVerification = Invoke-RemoteInstallPhase -Phase 'installed' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $InstalledReport = Assert-InstallDecision -Result $InstalledVerification -Expected 'installed_verified'

    $ServiceVerification = & $ServiceHarness -Commit $Commit -RunId $ServiceRunId -ServiceAuthorizationPath $ServiceAuthorizationPath -InstallTransactionId $TransactionId -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 900)) | ConvertFrom-Json
    if ([string]$ServiceVerification.decision -cne 'service_verified' -or -not [bool]$ServiceVerification.owned_cleanup_complete) { throw 'separate service acceptance did not complete exact cleanup' }

    $RollbackResult = Invoke-RemoteInstallPhase -Phase 'rollback' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $RollbackReport = Assert-InstallDecision -Result $RollbackResult -Expected 'rolled_back'
    $AfterState = Get-StableRealInstallState -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    Assert-RealInstallStateUnchanged -Before $BeforeState -After $AfterState
    Invoke-RealInstallCleanup -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
    $script:RealInstallCleanupComplete = $true
    $ResidueCount = [int](Invoke-RemoteInstallPhase -Phase 'residue' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath).Stdout.Trim()
    if ($ResidueCount -ne 0) { throw 'generated real-install residue remains' }

    [ordered]@{
        schema_version = 1
        decision = 'real_service_acceptance_verified'
        artifact_commit_sha = $Commit
        workflow_run_id = $Bundle.WorkflowRunId
        install_transaction_id = $TransactionId
        install_decision = [string]$ApplyReport.decision
        installed_check_decision = [string]$InstalledReport.decision
        service_decision = [string]$ServiceVerification.decision
        owned_cleanup_complete = [bool]$ServiceVerification.owned_cleanup_complete
        rollback_decision = [string]$RollbackReport.decision
        network_identity_before = [string]$BeforeState.network
        network_identity_after = [string]$AfterState.network
        ebpf_identity_before = [string]$BeforeState.ebpf
        ebpf_identity_after = [string]$AfterState.ebpf
        outside_install_state_unchanged = $true
        generated_residue_count = $ResidueCount
        mutations_performed = $true
    } | ConvertTo-Json -Depth 8 -Compress
}
finally {
    if (-not $script:RealInstallCleanupComplete) { try { & $CleanupAction } catch { Write-Warning $_.Exception.Message } }
    Unregister-RealInstallCleanup -CancelHandler $CancelHandler
}

