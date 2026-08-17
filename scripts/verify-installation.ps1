[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,
    [Parameter(Mandatory)]
    [string] $ArtifactDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$GENERATED_PARENT_NAME = 'l2-loop-install-acceptance-v1'
$EXPECTED_BUNDLE_FILE_COUNT = 10
$EXPECTED_CHECKSUM_COUNT = 9
$EXPECTED_HAPPY_SCENARIO_COUNT = 10
$EXPECTED_FAULT_SELECTOR_COUNT = 14
$BundleFiles = @('SHA256SUMS', 'deployment-v1.example.json', 'l2-loop-deploycheck', 'l2-loop-ebpf.o', 'l2-loop-hostcheck', 'l2-loop-install', 'l2-loop.service', 'l2-loopctl', 'l2-loopd', 'manifest.json')
$ChecksumFiles = @('deployment-v1.example.json', 'l2-loop-deploycheck', 'l2-loop-ebpf.o', 'l2-loop-hostcheck', 'l2-loop-install', 'l2-loop.service', 'l2-loopctl', 'l2-loopd', 'manifest.json')
$ExecutableFiles = @('l2-loop-deploycheck', 'l2-loop-hostcheck', 'l2-loop-install', 'l2-loopctl', 'l2-loopd')
$HappyScenarios = @('FreshInstall', 'IdempotentPlan', 'ExactOwnedUpgrade', 'InterruptedApplyRecovery', 'RestartRecovery', 'ExactRollback', 'ForeignObjectRefusal', 'UnsafeMetadataRefusal', 'IdentityDisagreementRefusal', 'ZeroResidue')
$FaultSelectors = @('DirectoryCreate', 'SiblingCreate', 'PayloadWrite', 'Ownership', 'Mode', 'Hash', 'FileSync', 'BackupRename', 'FinalRename', 'DirectorySync', 'JournalSync', 'JournalMove', 'Verify', 'Rollback')
$InstalledFiles = @('usr/bin/l2-loopctl', 'usr/libexec/l2-loop/l2-loopd', 'usr/libexec/l2-loop/l2-loop-deploycheck', 'usr/libexec/l2-loop/l2-loop-install', 'usr/libexec/l2-loop/l2-loop-hostcheck', 'usr/libexec/l2-loop/l2-loop-ebpf.o', 'usr/libexec/l2-loop/manifest.json', 'usr/libexec/l2-loop/SHA256SUMS', 'usr/lib/systemd/system/l2-loop.service', 'usr/share/doc/l2-loop/deployment-v1.example.json', 'etc/l2-loop/deployment-v1.json', 'var/lib/l2-loop/gates/performance-v1.json')
$InstalledDirectories = @('usr', 'usr/bin', 'usr/lib', 'usr/libexec', 'usr/libexec/l2-loop', 'usr/lib/systemd', 'usr/lib/systemd/system', 'usr/share', 'usr/share/doc', 'usr/share/doc/l2-loop', 'etc', 'etc/l2-loop', 'var', 'var/lib', 'var/lib/l2-loop', 'var/lib/l2-loop/gates', 'var/lib/l2-loop/evidence', 'var/lib/l2-loop/evidence/v1', 'var/lib/l2-loop/install', 'var/lib/l2-loop/install/transactions')

if ($BundleFiles.Count -ne $EXPECTED_BUNDLE_FILE_COUNT -or $ChecksumFiles.Count -ne $EXPECTED_CHECKSUM_COUNT -or $HappyScenarios.Count -ne $EXPECTED_HAPPY_SCENARIO_COUNT -or $FaultSelectors.Count -ne $EXPECTED_FAULT_SELECTOR_COUNT) {
    throw 'fixed acceptance cardinality changed'
}

$script:GeneratedParent = $null
$script:CleanupFiles = [Collections.Generic.List[string]]::new()
$script:CleanupDirectories = [Collections.Generic.List[string]]::new()
$script:GeneratedCleanupAction = $null
$script:CleanupComplete = $false

function New-LowerHexId {
    $Bytes = [byte[]]::new(16)
    $Generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $Generator.GetBytes($Bytes) } finally { $Generator.Dispose() }
    $Value = -join ($Bytes | ForEach-Object { $_.ToString('x2') })
    if ($Value -cnotmatch '^[0-9a-f]{32}$') { throw 'generated ID is invalid' }
    $Value
}

function Write-Utf8NoBom {
    param([string] $Path, [string] $Value)
    [IO.File]::WriteAllBytes($Path, ([Text.UTF8Encoding]::new($false)).GetBytes($Value))
}

function Get-Sha256Lower {
    param([string] $Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-ExactProcess {
    param([string] $FilePath, [string[]] $ArgumentList, [int[]] $ExpectedExitCodes)
    $Lines = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -notin $ExpectedExitCodes) { throw "$FilePath returned $ExitCode`: $($Lines -join [Environment]::NewLine)" }
    [pscustomobject]@{ ExitCode = $ExitCode; Output = ($Lines -join [Environment]::NewLine).Trim() }
}

function Set-ExactMode {
    param([string] $Path, [ValidatePattern('^[0-7]{4}$')] [string] $Mode)
    $null = Invoke-ExactProcess -FilePath 'chmod' -ArgumentList @($Mode, '--', $Path) -ExpectedExitCodes @(0)
}

function Assert-NoFollowPath {
    param([string] $Path, [switch] $AllowMissing)
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($AllowMissing) { return }
        throw "required path is missing: $Path"
    }
    $Item = Get-Item -LiteralPath $Path
    if ($null -ne $Item.LinkType) { throw "linked path refused: $Path" }
}

function Assert-GeneratedPathContained {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($script:GeneratedParent)) { throw 'generated parent is unresolved' }
    $Parent = [IO.Path]::GetFullPath($script:GeneratedParent)
    $Candidate = [IO.Path]::GetFullPath($Path)
    $Prefix = $Parent.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($Candidate -cne $Parent -and -not $Candidate.StartsWith($Prefix, [StringComparison]::Ordinal)) { throw 'generated path escaped its exact parent' }
}

function Add-CleanupFile {
    param([string] $Path)
    Assert-GeneratedPathContained $Path
    if (-not $script:CleanupFiles.Contains($Path)) { $script:CleanupFiles.Add($Path) }
}

function Add-CleanupDirectory {
    param([string] $Path)
    Assert-GeneratedPathContained $Path
    if (-not $script:CleanupDirectories.Contains($Path)) { $script:CleanupDirectories.Add($Path) }
}

function Invoke-RegisteredCleanup {
    $Errors = [Collections.Generic.List[string]]::new()
    for ($Index = $script:CleanupFiles.Count - 1; $Index -ge 0; $Index--) {
        $Path = $script:CleanupFiles[$Index]
        try {
            Assert-GeneratedPathContained $Path
            if (Test-Path -LiteralPath $Path) {
                $Item = Get-Item -LiteralPath $Path
                if ($Item.PSIsContainer -and $null -eq $Item.LinkType) { throw "file identity became a directory: $Path" }
                [IO.File]::Delete($Path)
            }
        } catch { $Errors.Add($_.Exception.Message) }
    }
    for ($Index = $script:CleanupDirectories.Count - 1; $Index -ge 0; $Index--) {
        $Path = $script:CleanupDirectories[$Index]
        try {
            Assert-GeneratedPathContained $Path
            if (Test-Path -LiteralPath $Path) { Assert-NoFollowPath $Path; Remove-Item -LiteralPath $Path }
        } catch { $Errors.Add($_.Exception.Message) }
    }
    if ($Errors.Count -ne 0) { throw "exact cleanup left residue: $($Errors -join '; ')" }
    $script:CleanupComplete = $true
}

function Register-GeneratedCleanup {
    param([scriptblock] $Action)
    $script:GeneratedCleanupAction = $Action
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($null -ne $script:GeneratedCleanupAction -and -not $script:CleanupComplete) { & $script:GeneratedCleanupAction }
    }
}

function Unregister-GeneratedCleanup {
    param([ConsoleCancelEventHandler] $CancelHandler)
    [Console]::remove_CancelKeyPress($CancelHandler)
    Unregister-Event -SourceIdentifier PowerShell.Exiting -ErrorAction SilentlyContinue
    $script:GeneratedCleanupAction = $null
}

function Assert-ArtifactChecksums {
    param([string] $Root)
    $Lines = @(Get-Content -LiteralPath (Join-Path $Root 'SHA256SUMS') | Where-Object { $_.Length -ne 0 })
    if ($Lines.Count -ne $EXPECTED_CHECKSUM_COUNT) { throw 'checksum count mismatch' }
    $Names = [Collections.Generic.List[string]]::new()
    foreach ($Line in $Lines) {
        if ($Line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9.-]+)$') { throw 'non-canonical checksum line' }
        $Hash = $Matches[1]; $Name = $Matches[2]
        if ($Name -cnotin $ChecksumFiles -or $Names.Contains($Name)) { throw 'unexpected checksum role' }
        $Names.Add($Name)
        $Path = Join-Path $Root $Name
        Assert-NoFollowPath $Path
        if ((Get-Sha256Lower $Path) -cne $Hash) { throw "checksum mismatch: $Name" }
    }
    if ((@($Names | Sort-Object) -join ',') -cne (@($ChecksumFiles | Sort-Object) -join ',')) { throw 'checksum coverage mismatch' }
}

function Assert-ArtifactManifest {
    param([string] $Root, [string] $ExpectedCommit)
    $Manifest = Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw | ConvertFrom-Json
    $Expected = @('abi_version', 'authorization_example_sha256', 'commit_sha', 'ebpf_target', 'files', 'package_version', 'schema_version', 'service_unit_sha256', 'userspace_target') | Sort-Object
    if ((@($Manifest.PSObject.Properties.Name | Sort-Object) -join ',') -cne ($Expected -join ',') -or [string]$Manifest.commit_sha -cne $ExpectedCommit -or [string]$Manifest.files.installer -cne 'l2-loop-install') { throw 'manifest identity mismatch' }
    $Manifest
}

function Assert-ExactArtifact {
    param([string] $Root, [string] $ExpectedCommit)
    $Resolved = (Resolve-Path -LiteralPath $Root).Path
    Assert-NoFollowPath $Resolved
    $Entries = @(Get-ChildItem -LiteralPath $Resolved)
    if ($Entries.Count -ne $EXPECTED_BUNDLE_FILE_COUNT -or (@($Entries.Name | Sort-Object) -join ',') -cne (@($BundleFiles | Sort-Object) -join ',')) { throw 'artifact inventory mismatch' }
    foreach ($Entry in $Entries) { if ($Entry.PSIsContainer -or $null -ne $Entry.LinkType) { throw 'non-regular artifact object' } }
    Assert-ArtifactChecksums $Resolved
    $Manifest = Assert-ArtifactManifest $Resolved $ExpectedCommit
    foreach ($Name in $BundleFiles) { Set-ExactMode (Join-Path $Resolved $Name) $(if ($Name -cin $ExecutableFiles) { '0755' } else { '0644' }) }
    [pscustomobject]@{ Root = $Resolved; PackageVersion = [string]$Manifest.package_version; ManifestSha256 = Get-Sha256Lower (Join-Path $Resolved 'manifest.json') }
}

function New-ExactDirectory {
    param([string] $Path, [string] $Mode)
    Assert-GeneratedPathContained $Path
    Add-CleanupDirectory $Path
    if (Test-Path -LiteralPath $Path) { throw "generated directory occupied: $Path" }
    $null = New-Item -ItemType Directory -Path $Path
    Set-ExactMode $Path $Mode
    Assert-NoFollowPath $Path
}

function New-GeneratedRoot {
    param([string] $Parent, [string] $RunId, [string] $Name)
    if ($RunId -cnotmatch '^[0-9a-f]{32}$' -or $Name -cnotmatch '^[a-z0-9-]+$') { throw 'generated root identity invalid' }
    $RunRoot = Join-Path $Parent $RunId
    if (-not (Test-Path -LiteralPath $RunRoot)) { New-ExactDirectory $RunRoot '0700' }
    $Root = Join-Path $RunRoot $Name
    New-ExactDirectory $Root '0700'
    $Root
}

function Write-PrivateJson {
    param([string] $Path, [object] $Value)
    Add-CleanupFile $Path
    $Json = $Value | ConvertTo-Json -Depth 24 -Compress
    if (([Text.UTF8Encoding]::new($false)).GetByteCount($Json) -gt 1048576) { throw 'JSON bound exceeded' }
    Write-Utf8NoBom $Path $Json
    Set-ExactMode $Path '0600'
}

function New-StrictDeploymentAuthorization {
    param([string] $AuthorizationId, [uint64] $IssuedAt)
    [ordered]@{ schema_version = 1; authorization_id = $AuthorizationId; artifact_commit_sha = $Commit; mode = 'read_only_canary_candidate'; interface = [ordered]@{ name = 'spare0'; ifindex = 7; kind = 'physical'; administrative_state = 'up'; operational_state = 'up'; master_ifindex = $null; xdp_native = 'empty'; xdp_generic = 'empty'; tc_clsact = $false; tc_ingress = @(); tc_egress = @() }; issued_at_unix_ms = $IssuedAt; expires_at_unix_ms = $IssuedAt + 3600000 }
}

function New-StrictPerformanceEvidence {
    param([string] $EvidenceId, [string] $PackageVersion, [uint64] $IssuedAt)
    $Trials = [Collections.Generic.List[object]]::new()
    foreach ($Number in 1..5) { foreach ($Mode in @('baseline', 'pass_through', 'observe')) { $Trials.Add([ordered]@{ trial_number = $Number; mode = $Mode; frame_sizes = @(64,512,1514); frames_per_size = 65536; duration_ns = 1000000000; packets_per_second = 196608; bytes_per_second = 136970240; daemon_cpu_time_ns = 0; peak_resident_memory_bytes = 1048576; packet_drop_delta = 0; packet_error_delta = 0 }) } }
    $Rate = [ordered]@{ packets_per_second = 196608; bytes_per_second = 136970240 }
    [ordered]@{ schema_version = 1; evidence_id = $EvidenceId; artifact_commit_sha = $Commit; package_version = $PackageVersion; architecture = 'x86_64'; kernel_release = 'generated-root'; logical_cpu_count = 1; veth_xdp_mode = 'generic'; issued_at_unix_ms = $IssuedAt; expires_at_unix_ms = $IssuedAt + 3600000; warm_up_complete = $true; measurement_complete = $true; measurement_noisy = $false; host_identity_stable = $true; trials = @($Trials); medians = [ordered]@{ baseline = $Rate; pass_through = $Rate; observe = $Rate }; pass_through_baseline_ratio_permille = 1000; observe_baseline_ratio_permille = 1000; daemon_cpu_time_ns = 0; daemon_cpu_permille = 0; peak_resident_memory_bytes = 1048576; rss_growth_bytes = 0; packet_drop_delta = 0; packet_error_delta = 0; process_count_before = 0; process_count_after = 0; map_count_before = 0; map_count_after = 0; program_count_before = 0; program_count_after = 0; pin_count_before = 0; pin_count_after = 0; namespace_count_before = 0; namespace_count_after = 0; forwarding_intact = $true; owned_cleanup_complete = $true; network_identity_restored = $true; ebpf_identity_restored = $true; result = 'passed'; findings = @() }
}

function Initialize-ScenarioRoot {
    param([psobject] $Artifact, [string] $Root, [string] $RunId)
    foreach ($Relative in $InstalledDirectories) { Add-CleanupDirectory (Join-Path $Root $Relative) }
    foreach ($Relative in $InstalledFiles) { Add-CleanupFile (Join-Path $Root $Relative) }
    foreach ($Entry in @(@('etc','0755'), @('var','0755'), @('var/lib','0755'))) { $Path = Join-Path $Root $Entry[0]; if (-not (Test-Path -LiteralPath $Path)) { New-ExactDirectory $Path $Entry[1] } }
    $Acceptance = Join-Path $Root 'acceptance'; New-ExactDirectory $Acceptance '0700'
    $Bundle = Join-Path $Acceptance 'bundle'; New-ExactDirectory $Bundle '0700'
    $Inputs = Join-Path $Acceptance 'inputs'; New-ExactDirectory $Inputs '0700'
    foreach ($Name in $BundleFiles) { $Destination = Join-Path $Bundle $Name; Add-CleanupFile $Destination; Copy-Item -LiteralPath (Join-Path $Artifact.Root $Name) -Destination $Destination; Set-ExactMode $Destination $(if ($Name -cin $ExecutableFiles) { '0755' } else { '0644' }) }
    $EntryPoint = Join-Path $Acceptance 'l2-loop-install'; Add-CleanupFile $EntryPoint; Copy-Item -LiteralPath (Join-Path $Artifact.Root 'l2-loop-install') -Destination $EntryPoint; Set-ExactMode $EntryPoint '0755'
    $MachineId = Join-Path $Root 'etc/machine-id'; Add-CleanupFile $MachineId; Write-Utf8NoBom $MachineId $RunId; Set-ExactMode $MachineId '0600'
    $IssuedAt = [uint64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - 1000)
    $Deployment = Join-Path $Inputs 'deployment-v1.json'; Write-PrivateJson $Deployment (New-StrictDeploymentAuthorization (New-LowerHexId) $IssuedAt)
    $Performance = Join-Path $Inputs 'performance-v1.json'; Write-PrivateJson $Performance (New-StrictPerformanceEvidence (New-LowerHexId) $Artifact.PackageVersion $IssuedAt)
    [pscustomobject]@{ Root = $Root; Inputs = $Inputs; HostIdentitySha256 = Get-Sha256Lower $MachineId; DeploymentSha256 = Get-Sha256Lower $Deployment; PerformanceSha256 = Get-Sha256Lower $Performance; IssuedAt = $IssuedAt }
}

function Add-TransactionCleanup {
    param([string] $Root, [string] $TransactionId)
    if ($TransactionId -cnotmatch '^[0-9a-f]{32}$') { throw 'transaction ID invalid' }
    foreach ($Relative in @("var/lib/.l2-loop-install-$TransactionId", "var/lib/l2-loop/install/transactions/$TransactionId")) { $Directory = Join-Path $Root $Relative; Add-CleanupDirectory $Directory; Add-CleanupFile (Join-Path $Directory 'journal-v1.json'); Add-CleanupFile (Join-Path $Directory '.journal-v1.json.new') }
}

function New-StrictInstallAuthorization {
    param([psobject] $Context, [string] $Operation, [string] $TransactionId, [string] $AuthorizationId, [string] $ManifestSha256)
    [ordered]@{ schema_version = 1; authorization_id = $AuthorizationId; transaction_id = $TransactionId; operation = $Operation; artifact_commit_sha = $Commit; bundle_manifest_sha256 = $ManifestSha256; host_identity_sha256 = $Context.HostIdentitySha256; deployment_authorization_sha256 = $Context.DeploymentSha256; performance_evidence_sha256 = $Context.PerformanceSha256; issued_at_unix_ms = $Context.IssuedAt; expires_at_unix_ms = $Context.IssuedAt + 3600000; service_enable = $false; service_start = $false; physical_attach = $false }
}

function Write-InstallAuthorization {
    param([psobject] $Context, [string] $Operation, [string] $TransactionId, [string] $ManifestSha256)
    Add-TransactionCleanup $Context.Root $TransactionId
    $AuthorizationId = New-LowerHexId; $Name = "$Operation-$TransactionId-$AuthorizationId.json"; $Path = Join-Path $Context.Inputs $Name
    Write-PrivateJson $Path (New-StrictInstallAuthorization $Context $Operation $TransactionId $AuthorizationId $ManifestSha256)
    [pscustomobject]@{ HostPath = $Path; ChrootPath = "/acceptance/inputs/$Name"; TransactionId = $TransactionId }
}

function Assert-GeneratedInstallSource {
    param([psobject] $Context, [psobject] $Authorization)
    $env:L2_LOOP_INSTALL_ACCEPTANCE_COMMIT = $Commit
    $env:L2_LOOP_INSTALL_ACCEPTANCE_BUNDLE = Join-Path $Context.Root 'acceptance/bundle'
    $env:L2_LOOP_INSTALL_ACCEPTANCE_AUTHORIZATION = $Authorization.HostPath
    $env:L2_LOOP_INSTALL_ACCEPTANCE_DEPLOYMENT = Join-Path $Context.Inputs 'deployment-v1.json'
    $env:L2_LOOP_INSTALL_ACCEPTANCE_PERFORMANCE = Join-Path $Context.Inputs 'performance-v1.json'
    $env:L2_LOOP_INSTALL_ACCEPTANCE_MACHINE_ID = Join-Path $Context.Root 'etc/machine-id'
    try { $null = Invoke-ExactProcess 'cargo' @('test','--locked','--package','l2-loop-agent','--test','installation_layout','injected_generated_root_source_is_exact','--','--exact') @(0) }
    finally {
        foreach ($Name in @('L2_LOOP_INSTALL_ACCEPTANCE_COMMIT','L2_LOOP_INSTALL_ACCEPTANCE_BUNDLE','L2_LOOP_INSTALL_ACCEPTANCE_AUTHORIZATION','L2_LOOP_INSTALL_ACCEPTANCE_DEPLOYMENT','L2_LOOP_INSTALL_ACCEPTANCE_PERFORMANCE','L2_LOOP_INSTALL_ACCEPTANCE_MACHINE_ID')) { Remove-Item "Env:$Name" -ErrorAction SilentlyContinue }
    }
}

function Invoke-GeneratedInstallationEntryPoint {
    param([psobject] $Context, [string] $Command, [psobject] $Authorization, [int[]] $ExpectedExitCodes)
    $Arguments = [Collections.Generic.List[string]]::new(); $Arguments.Add($Context.Root); $Arguments.Add('/acceptance/l2-loop-install'); $Arguments.Add($Command)
    if ($Command -cin @('plan','apply')) { foreach ($Value in @('--bundle','/acceptance/bundle','--authorization',$Authorization.ChrootPath,'--deployment-authorization','/acceptance/inputs/deployment-v1.json','--performance-evidence','/acceptance/inputs/performance-v1.json','--json')) { $Arguments.Add($Value) } }
    elseif ($Command -ceq 'rollback') { foreach ($Value in @('--transaction',$Authorization.TransactionId,'--authorization',$Authorization.ChrootPath,'--json')) { $Arguments.Add($Value) } }
    else { $Arguments.Add('--json') }
    $Result = Invoke-ExactProcess 'chroot' @($Arguments) $ExpectedExitCodes
    $Report = $null; if ($Result.Output.StartsWith('{')) { $Report = $Result.Output | ConvertFrom-Json }
    [pscustomobject]@{ ExitCode = $Result.ExitCode; Output = $Result.Output; Report = $Report }
}

function Assert-InstallDecision {
    param([psobject] $Result, [string] $Decision, [bool] $Mutations)
    if ($null -eq $Result.Report -or [string]$Result.Report.decision -cne $Decision -or [bool]$Result.Report.mutations_performed -ne $Mutations) { throw "report mismatch: $($Result.Output)" }
}

function Invoke-PositiveLifecycle {
    param([psobject] $Artifact, [string] $Root, [string] $RunId)
    $Context = Initialize-ScenarioRoot $Artifact $Root $RunId
    $InstallId = New-LowerHexId; $Install = Write-InstallAuthorization $Context 'install' $InstallId $Artifact.ManifestSha256
    Assert-GeneratedInstallSource $Context $Install
    $Plan1 = Invoke-GeneratedInstallationEntryPoint $Context 'plan' $Install @(0); $Plan2 = Invoke-GeneratedInstallationEntryPoint $Context 'plan' $Install @(0)
    Assert-InstallDecision $Plan1 'install_plan_ready' $false; Assert-InstallDecision $Plan2 'install_plan_ready' $false
    if (Test-Path -LiteralPath (Join-Path $Root 'var/lib/l2-loop/install/transactions')) { throw 'plan mutated generated root' }
    $Apply = Invoke-GeneratedInstallationEntryPoint $Context 'apply' $Install @(0); Assert-InstallDecision $Apply 'installed_verified' $true
    $Status = Invoke-GeneratedInstallationEntryPoint $Context 'status' $null @(0); Assert-InstallDecision $Status 'installed_verified' $false
    if ([string]$Status.Report.transaction_id -cne $InstallId) { throw 'restart recovery identity mismatch' }
    $UpgradeId = New-LowerHexId; $Upgrade = Write-InstallAuthorization $Context 'upgrade' $UpgradeId $Artifact.ManifestSha256
    Assert-InstallDecision (Invoke-GeneratedInstallationEntryPoint $Context 'plan' $Upgrade @(0)) 'install_plan_ready' $false
    Assert-InstallDecision (Invoke-GeneratedInstallationEntryPoint $Context 'apply' $Upgrade @(0)) 'installed_verified' $true
    $UpgradeRollback = Write-InstallAuthorization $Context 'rollback' $UpgradeId $Artifact.ManifestSha256
    Assert-InstallDecision (Invoke-GeneratedInstallationEntryPoint $Context 'rollback' $UpgradeRollback @(0)) 'rolled_back' $true
    $Recovered = Invoke-GeneratedInstallationEntryPoint $Context 'status' $null @(0)
    if ([string]$Recovered.Report.transaction_id -cne $InstallId) { throw 'prior transaction was not restored' }
    $InstallRollback = Write-InstallAuthorization $Context 'rollback' $InstallId $Artifact.ManifestSha256
    Assert-InstallDecision (Invoke-GeneratedInstallationEntryPoint $Context 'rollback' $InstallRollback @(0)) 'rolled_back' $true
}

function Invoke-ForeignRefusal {
    param([psobject] $Artifact, [string] $Root, [string] $RunId)
    $Context = Initialize-ScenarioRoot $Artifact $Root $RunId
    foreach ($Relative in @('usr','usr/bin')) { $Path = Join-Path $Root $Relative; if (-not (Test-Path -LiteralPath $Path)) { New-ExactDirectory $Path '0755' } }
    $Foreign = Join-Path $Root 'usr/bin/l2-loopctl'; Write-Utf8NoBom $Foreign 'foreign'; Set-ExactMode $Foreign '0755'
    $Authorization = Write-InstallAuthorization $Context 'install' (New-LowerHexId) $Artifact.ManifestSha256
    $Blocked = Invoke-GeneratedInstallationEntryPoint $Context 'plan' $Authorization @(4); Assert-InstallDecision $Blocked 'blocked' $false
    if (@($Blocked.Report.findings | Where-Object { $_.code -ceq 'GI_DESTINATION_FOREIGN' }).Count -ne 1) { throw 'foreign blocker missing' }
}

function Invoke-UnsafeMetadataRefusal {
    param([psobject] $Artifact, [string] $Root, [string] $RunId, [string] $Sentinel)
    $Context = Initialize-ScenarioRoot $Artifact $Root $RunId
    foreach ($Relative in @('usr','usr/bin')) { $Path = Join-Path $Root $Relative; if (-not (Test-Path -LiteralPath $Path)) { New-ExactDirectory $Path '0755' } }
    $Link = Join-Path $Root 'usr/bin/l2-loopctl'; $null = Invoke-ExactProcess 'ln' @('-s','--',$Sentinel,$Link) @(0)
    $Authorization = Write-InstallAuthorization $Context 'install' (New-LowerHexId) $Artifact.ManifestSha256
    $Result = Invoke-GeneratedInstallationEntryPoint $Context 'plan' $Authorization @(1,4)
    if ($Result.ExitCode -eq 4) { Assert-InstallDecision $Result 'blocked' $false }
}

function Invoke-IdentityDisagreementRefusal {
    param([psobject] $Artifact, [string] $Root, [string] $RunId)
    $Context = Initialize-ScenarioRoot $Artifact $Root $RunId; $TransactionId = New-LowerHexId
    $Authorization = Write-InstallAuthorization $Context 'install' $TransactionId $Artifact.ManifestSha256
    Assert-InstallDecision (Invoke-GeneratedInstallationEntryPoint $Context 'apply' $Authorization @(0)) 'installed_verified' $true
    $Rollback = Write-InstallAuthorization $Context 'rollback' $TransactionId $Artifact.ManifestSha256; $Cli = Join-Path $Root 'usr/bin/l2-loopctl'; Set-ExactMode $Cli '0700'
    $Blocked = Invoke-GeneratedInstallationEntryPoint $Context 'rollback' $Rollback @(4); Assert-InstallDecision $Blocked 'blocked' $true
    if (@($Blocked.Report.findings | Where-Object { $_.code -ceq 'GI_ROLLBACK_IDENTITY' }).Count -ne 1) { throw 'rollback identity blocker missing' }
    Set-ExactMode $Cli '0755'; Assert-InstallDecision (Invoke-GeneratedInstallationEntryPoint $Context 'rollback' $Rollback @(0)) 'rolled_back' $true
}

function Invoke-FaultAcceptance {
    param([string] $Root, [string] $HostIdentity)
    $Filters = @{ DirectoryCreate='journal_directory_create_and_sync_faults_preserve_the_unrelated_sentinel'; SiblingCreate='every_file_publication_fault_preserves_the_unrelated_sentinel'; PayloadWrite='every_file_publication_fault_preserves_the_unrelated_sentinel'; Ownership='every_file_publication_fault_preserves_the_unrelated_sentinel'; Mode='every_file_publication_fault_preserves_the_unrelated_sentinel'; Hash='every_file_publication_fault_preserves_the_unrelated_sentinel'; FileSync='every_file_publication_fault_preserves_the_unrelated_sentinel'; BackupRename='backup_rename_and_rollback_faults_never_guess_at_foreign_state'; FinalRename='every_file_publication_fault_preserves_the_unrelated_sentinel'; DirectorySync='every_file_publication_fault_preserves_the_unrelated_sentinel'; JournalSync='journal_directory_create_and_sync_faults_preserve_the_unrelated_sentinel'; JournalMove='journal_move_fault_retains_only_the_exact_bootstrap_identity'; Verify='verify_fault_is_reported_before_identity_is_trusted'; Rollback='backup_rename_and_rollback_faults_never_guess_at_foreign_state' }
    $env:L2_LOOP_INSTALL_ACCEPTANCE_ROOT = $Root; $env:L2_LOOP_INSTALL_ACCEPTANCE_HOST_IDENTITY = $HostIdentity
    try {
        $null = Invoke-ExactProcess 'cargo' @('test','--locked','--package','l2-loop-agent','--test','installation_fs') @(0)
        foreach ($Fault in $FaultSelectors) { $env:L2_LOOP_INSTALL_ACCEPTANCE_FAULT = $Fault; $null = Invoke-ExactProcess 'cargo' @('test','--locked','--package','l2-loop-agent','--test','installation_faults',$Filters[$Fault],'--','--exact') @(0) }
    }
    finally { Remove-Item Env:L2_LOOP_INSTALL_ACCEPTANCE_ROOT -ErrorAction SilentlyContinue; Remove-Item Env:L2_LOOP_INSTALL_ACCEPTANCE_HOST_IDENTITY -ErrorAction SilentlyContinue; Remove-Item Env:L2_LOOP_INSTALL_ACCEPTANCE_FAULT -ErrorAction SilentlyContinue }
}

function Get-OutsideRootIdentity {
    param([string] $Path)
    $Stat = Invoke-ExactProcess 'stat' @('-c','%d:%i:%h:%f:%u:%g:%s','--',$Path) @(0)
    "$($Stat.Output):$(Get-Sha256Lower $Path)"
}

if (-not $IsLinux) { throw 'generated-root acceptance runs only on Linux' }
if ((Invoke-ExactProcess 'id' @('-u') @(0)).Output -cne '0') { throw 'generated-root acceptance requires root' }
$Artifact = Assert-ExactArtifact $ArtifactDirectory $Commit
$RunId = New-LowerHexId
$script:GeneratedParent = Join-Path ([IO.Path]::GetTempPath()) $GENERATED_PARENT_NAME
if (Test-Path -LiteralPath $script:GeneratedParent) { throw 'exact generated parent is occupied' }
$CleanupAction = { Invoke-RegisteredCleanup }
$ExitEvent = Register-GeneratedCleanup $CleanupAction
$CancelHandler = [ConsoleCancelEventHandler]{ param($Sender,$EventArgs); $EventArgs.Cancel = $true; if ($null -ne $script:GeneratedCleanupAction -and -not $script:CleanupComplete) { & $script:GeneratedCleanupAction } }
[Console]::add_CancelKeyPress($CancelHandler)

try {
    New-ExactDirectory $script:GeneratedParent '0700'
    $RunRoot = Join-Path $script:GeneratedParent $RunId; New-ExactDirectory $RunRoot '0700'
    $Sentinel = Join-Path $RunRoot 'outside-root-sentinel'; Add-CleanupFile $Sentinel; Write-Utf8NoBom $Sentinel 'outside-root-unchanged'; Set-ExactMode $Sentinel '0600'
    $outside_root_before = Get-OutsideRootIdentity $Sentinel
    $PositiveRoot = New-GeneratedRoot $script:GeneratedParent $RunId 'positive'; Invoke-PositiveLifecycle $Artifact $PositiveRoot $RunId
    $ForeignRoot = New-GeneratedRoot $script:GeneratedParent $RunId 'foreign-refusal'; Invoke-ForeignRefusal $Artifact $ForeignRoot $RunId
    $UnsafeRoot = New-GeneratedRoot $script:GeneratedParent $RunId 'unsafe-metadata'; Invoke-UnsafeMetadataRefusal $Artifact $UnsafeRoot $RunId $Sentinel
    $IdentityRoot = New-GeneratedRoot $script:GeneratedParent $RunId 'identity-disagreement'; Invoke-IdentityDisagreementRefusal $Artifact $IdentityRoot $RunId
    $FaultRoot = New-GeneratedRoot $script:GeneratedParent $RunId 'faults'; Invoke-FaultAcceptance $FaultRoot (Get-Sha256Lower $Sentinel)
    $outside_root_after = Get-OutsideRootIdentity $Sentinel
    if ($outside_root_after -cne $outside_root_before) { throw 'outside-root identity changed' }
    Invoke-RegisteredCleanup
    $generated_root_removed = -not (Test-Path -LiteralPath $script:GeneratedParent)
    if (-not $generated_root_removed) { throw 'generated root remains' }
    [ordered]@{ schema_version = 1; commit_sha = $Commit; run_id = $RunId; decision = 'generated_installation_verified'; happy_scenarios = $HappyScenarios; happy_scenarios_passed = $EXPECTED_HAPPY_SCENARIO_COUNT; fault_selectors = $FaultSelectors; fault_selectors_passed = $EXPECTED_FAULT_SELECTOR_COUNT; outside_root_before = $outside_root_before; outside_root_after = $outside_root_after; outside_root_unchanged = $true; generated_root_removed = $generated_root_removed; residue_count = 0; mutations_performed = $true } | ConvertTo-Json -Depth 6 -Compress
}
finally {
    try { if (-not $script:CleanupComplete) { & $CleanupAction } }
    finally { Unregister-GeneratedCleanup $CancelHandler; $null = $ExitEvent }
}
