# Separate Real-Node Acceptance Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make real fixed-path installation/rollback and generated-veth systemd/journald acceptance two independently authorized, independently invoked, fail-closed operational gates.

**Architecture:** Keep two explicit controller entry points. `verify-real-install.ps1` becomes Gate 1 and contains no service authorization or service invocation. The current combined transaction flow is preserved under the new Gate 2 entry point `verify-real-service-acceptance.ps1`, where a completely fresh install/service/rollback authorization set establishes the fixed-path prerequisite, runs the existing narrow generated-veth service harness, and rolls the Gate 2 transaction back. Static tests inspect each controller separately so later changes cannot silently reconnect the gates.

**Tech Stack:** PowerShell 7 and Windows PowerShell 5.1 static safety tests, bounded Bash over SSH embedded in PowerShell, GitHub Actions, existing Rust MUSL artifact and `l2-loop-install`/`l2-loop-deploycheck` binaries.

## Global Constraints

- Work directly on `main`; do not create a branch, worktree, pull request, or subagent.
- Use `apply_patch` for every source, test, workflow, and documentation edit.
- Do not compile, format, lint, or test Rust locally. RED and GREEN evidence comes only from the exact GitHub commit.
- Do not connect to a node during implementation. Do not run either real-node controller.
- Do not start, stop, enable, disable, or reload a real service during implementation.
- Do not create or alter a network interface, network namespace, XDP/TC hook, eBPF program, Map, or pin during implementation.
- Gate 1 and Gate 2 use new, non-reused authorization IDs and transaction IDs. Neither controller automatically invokes a later gate.
- Every remote path, generated name, timeout, output bound, cleanup target, and mutation remains fixed and identity-exact.
- No controller accepts a physical-interface argument, discovers a default route, replaces a hook, performs foreign cleanup, or uses recursive/wildcard cleanup.
- Gate 3 remains read-only and absent from these controllers. Gate 4 remains unimplemented, separately designed, and bounded to at most 15 minutes.
- Successful implementation does not provide real `installed_verified`, `service_verified`, or `physical_canary_ready` evidence and does not make the product production-ready.

---

### Task 1: Specify the Gate 1 boundary with a RED test

**Files:**
- Modify: `scripts/tests/verify-real-install.Tests.ps1`

**Interfaces:**
- Consumes: current combined `scripts/verify-real-install.ps1`.
- Produces: static assertions defining a Gate 1-only parameter surface, sequence, report, and prohibited service behavior.

- [x] **Step 1: Replace service-positive assertions with Gate 1-negative assertions**

Remove `ServiceAuthorizationPath`, `service_verified`, `verify-installed-service.ps1`, `$ServiceVerification = & $ServiceHarness`, and `service_decision` from the required-marker list. Add the following explicit negative checks after the ordering assertions:

```powershell
foreach ($ServiceMarker in @(
    'ServiceAuthorizationPath',
    '$ServiceHarness',
    'verify-installed-service.ps1',
    '$ServiceVerification',
    'service_decision',
    'service_verified',
    'service.json'
)) {
    Assert-True (-not $Harness.Contains($ServiceMarker)) "Gate 1 crosses the service-acceptance boundary: $ServiceMarker"
}
```

Change the required ordering to prove rollback follows installed verification directly:

```powershell
$InstalledIndex = $Harness.IndexOf('$InstalledVerification = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
$RollbackIndex = $Harness.IndexOf('$RollbackResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
Assert-True ($InstalledIndex -gt $ApplyIndex) 'installed layout is checked before apply'
Assert-True ($RollbackIndex -gt $InstalledIndex) 'exact rollback is not sequenced after installed verification'
```

Retain required markers for exact artifact validation, install/rollback authorization, stable network/eBPF snapshots, plan/apply/installed/rollback, `real_install_verified`, bounded output, exact cleanup, and zero generated residue.

- [x] **Step 2: Commit and push the RED test**

Run only repository inspection locally:

```powershell
git diff --check
git status --short
git add -- scripts/tests/verify-real-install.Tests.ps1
git commit -m "test: specify standalone real installation gate"
git push origin main
```

- [x] **Step 3: Verify the expected RED result in GitHub**

Run:

```powershell
$Commit = git rev-parse HEAD
$Run = gh run list --branch main --commit $Commit --limit 5 --json databaseId,status,conclusion,headSha,url | ConvertFrom-Json | Select-Object -First 1
gh run watch ([string]$Run.databaseId) --exit-status
```

Expected: `Script safety` and `Windows PowerShell safety` fail because the current Gate 1 script still contains service authorization, invocation, and report markers. Confirm the failures are the new Gate 1 assertions, while no real-node command is executed.

**Task 1 RED evidence:** Commit `5a72c568255e55c32532eeecf3ea7e6557215ab0`, GitHub run `32010264829`. `Script safety` job `95328129993` and `Windows PowerShell safety` job `95328130056` both failed in the real-install safety test. The Linux log reported exactly seven still-present Gate 2 markers: `ServiceAuthorizationPath`, `$ServiceHarness`, `verify-installed-service.ps1`, `$ServiceVerification`, `service_decision`, `service_verified`, and `service.json`. This proves the new test detects the pre-split controller. No real-node command ran.

---

### Task 2: Make Gate 1 installation/rollback-only and reach GREEN

**Files:**
- Modify: `scripts/verify-real-install.ps1`
- Modify: `docs/superpowers/plans/2026-08-17-separate-real-node-acceptance-gates.md`

**Interfaces:**
- Consumes: the RED contract from Task 1.
- Produces: `verify-real-install.ps1 -Commit -InstallAuthorizationPath -RollbackAuthorizationPath -DeploymentAuthorizationPath -PerformanceEvidencePath [-TimeoutSeconds]` returning Schema 1 `real_install_verified`.

- [x] **Step 1: Remove Gate 2 inputs and setup from Gate 1**

Delete this parameter:

```powershell
[Parameter(Mandatory)] [string] $ServiceAuthorizationPath,
```

Delete the service harness binding and generated service run ID:

```powershell
$ServiceHarness = Join-Path $PSScriptRoot 'verify-installed-service.ps1'
$ServiceRunId = New-InstallRunId
```

- [x] **Step 2: Narrow copied authorization inputs**

Replace the five-input copy table with exactly four inputs:

```powershell
$InputSources = @(
    $InstallAuthorizationPath,
    $RollbackAuthorizationPath,
    $DeploymentAuthorizationPath,
    $PerformanceEvidencePath
) | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
$InputNames = @('install.json','rollback.json','deployment.json','performance.json')
```

Change the embedded generated-root cleanup leaf list to the same four JSON files:

```bash
for leaf in install.json rollback.json deployment.json performance.json; do
    test ! -e "$inputs/$leaf" || unlink -- "$inputs/$leaf"
done
```

- [x] **Step 3: Remove the service call and narrow the report**

After `installed_verified`, invoke rollback immediately:

```powershell
$RollbackResult = Invoke-RemoteInstallPhase -Phase 'rollback' -Names $Names -TransactionId $TransactionId -Target $Target -KeyPath $KeyPath
$RollbackReport = Assert-InstallDecision -Result $RollbackResult -Expected 'rolled_back'
```

Emit exactly these decision fields, with the existing identity and residue fields retained:

```powershell
[ordered]@{
    schema_version = 1
    decision = 'real_install_verified'
    artifact_commit_sha = $Commit
    workflow_run_id = $Bundle.WorkflowRunId
    install_transaction_id = $TransactionId
    install_decision = [string]$ApplyReport.decision
    installed_check_decision = [string]$InstalledReport.decision
    rollback_decision = [string]$RollbackReport.decision
    network_identity_before = [string]$BeforeState.network
    network_identity_after = [string]$AfterState.network
    ebpf_identity_before = [string]$BeforeState.ebpf
    ebpf_identity_after = [string]$AfterState.ebpf
    outside_install_state_unchanged = $true
    generated_residue_count = $ResidueCount
    mutations_performed = $true
} | ConvertTo-Json -Depth 8 -Compress
```

- [x] **Step 4: Record Task 1 RED evidence and push GREEN**

Add the exact RED commit, run ID, failed jobs, and expected assertion messages to this plan. Then run:

```powershell
git diff --check
git add -- scripts/verify-real-install.ps1 docs/superpowers/plans/2026-08-17-separate-real-node-acceptance-gates.md
git commit -m "fix: isolate real installation acceptance gate"
git push origin main
```

- [x] **Step 5: Require all five GitHub jobs**

Use the exact GREEN commit with `gh run list` and `gh run watch`. Expected: Userspace, eBPF, Script safety, Windows PowerShell safety, and Bundle all succeed. Record the exact commit and run in this plan before continuing.

**Task 2 GREEN evidence:** Commit `52e7670a77671609cbca043e759c510d5b6b6d2a`, GitHub run `32010457161`. Userspace, eBPF, Script safety, Windows PowerShell safety, and Bundle all succeeded. The Gate 1 script contains none of the seven service-boundary markers and retains exact plan/apply/installed/rollback ordering. No real-node command ran.

---

### Task 3: Specify the separately authorized Gate 2 controller with a RED test

**Files:**
- Create: `scripts/tests/verify-real-service-acceptance.Tests.ps1`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the existing narrow inner `scripts/verify-installed-service.ps1` and a fresh Gate 2 install/service/rollback authorization set.
- Produces: static assertions for a new outer `scripts/verify-real-service-acceptance.ps1` controller and permanent Linux/Windows CI coverage.

- [x] **Step 1: Create the Gate 2 static safety test**

Use the same bounded `Assert-True` pattern as the other script tests. Resolve:

```powershell
$HarnessPath = Join-Path $RepositoryRoot 'scripts/verify-real-service-acceptance.ps1'
$InnerHarnessPath = Join-Path $RepositoryRoot 'scripts/verify-installed-service.ps1'
```

Require the outer controller to contain all of these markers:

```powershell
$Required = @(
    "[ValidatePattern('^[0-9a-f]{40}$')]",
    'InstallAuthorizationPath', 'RollbackAuthorizationPath',
    'ServiceAuthorizationPath', 'DeploymentAuthorizationPath',
    'PerformanceEvidencePath', 'L2_LOOP_TEST_TARGET', 'L2_LOOP_TEST_KEY',
    '$EXPECTED_BUNDLE_FILE_COUNT = 10', '$EXPECTED_CHECKSUM_COUNT = 9',
    'Assert-StrictInstallAuthorization', 'Get-StableRealInstallState',
    'Assert-RealInstallStateUnchanged', 'ControllerOwnershipNonce',
    'verify-installed-service.ps1', 'installed_verified', 'service_verified',
    'rolled_back', 'real_service_acceptance_verified',
    'outside_install_state_unchanged', 'owned_cleanup_complete',
    'generated_residue_count', 'schema_version = 1'
)
```

Require this exact ordering:

```powershell
$PlanIndex = $Harness.IndexOf('$PlanResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
$ApplyIndex = $Harness.IndexOf('$ApplyResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
$InstalledIndex = $Harness.IndexOf('$InstalledVerification = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
$ServiceIndex = $Harness.IndexOf('$ServiceVerification = & $ServiceHarness', [StringComparison]::Ordinal)
$RollbackIndex = $Harness.IndexOf('$RollbackResult = Invoke-RemoteInstallPhase', [StringComparison]::Ordinal)
Assert-True ($ApplyIndex -gt $PlanIndex) 'Gate 2 apply does not follow plan'
Assert-True ($InstalledIndex -gt $ApplyIndex) 'Gate 2 installed verification does not follow apply'
Assert-True ($ServiceIndex -gt $InstalledIndex) 'Gate 2 service can run before installed verification'
Assert-True ($RollbackIndex -gt $ServiceIndex) 'Gate 2 rollback does not follow service acceptance'
```

Require unique service cleanup evidence in the report:

```powershell
Assert-True ($Harness.Contains('owned_cleanup_complete = [bool]$ServiceVerification.owned_cleanup_complete')) 'Gate 2 does not propagate exact service cleanup evidence'
```

Reuse the prohibited regex set for interface parameters, default-route discovery, service enable/disable/restart, package/kernel/offload mutation, broad process killing, recursive/wildcard cleanup, force/repair/adopt, embedded IP addresses, and embedded `.ssh` paths.

- [x] **Step 2: Register the new test in both script jobs**

Add these exact workflow steps after the existing installed-service tests:

```yaml
- name: Test real service acceptance harness safety
  run: pwsh -NoProfile -File scripts/tests/verify-real-service-acceptance.Tests.ps1
```

```yaml
- name: Test real service acceptance harness with Windows PowerShell
  shell: powershell
  run: powershell -NoProfile -File scripts/tests/verify-real-service-acceptance.Tests.ps1
```

- [x] **Step 3: Commit, push, and prove RED**

```powershell
git diff --check
git add -- scripts/tests/verify-real-service-acceptance.Tests.ps1 .github/workflows/ci.yml
git commit -m "test: specify separate real service gate"
git push origin main
```

Expected GitHub result: Script safety and Windows PowerShell safety fail only because `scripts/verify-real-service-acceptance.ps1` is absent. Record exact commit, run, jobs, and missing-harness messages.

**Task 3 RED evidence:** Commit `527fe34767071ac6797442543f9ac1c2ed079bf3`, GitHub run `32011238550`. `Script safety` job `95331054932` and `Windows PowerShell safety` job `95331055000` both failed only in the newly registered real-service acceptance step. The Linux log reported `real service acceptance harness is missing` and exactly one failed assertion. No real-node command ran.

---

### Task 4: Implement Gate 2 with a fresh transaction and reach GREEN

**Files:**
- Create: `scripts/verify-real-service-acceptance.ps1`
- Modify: `docs/superpowers/plans/2026-08-17-separate-real-node-acceptance-gates.md`

**Interfaces:**
- Consumes: exact GitHub artifact, fresh Gate 2 install/service/rollback authorizations, deployment authorization, performance evidence, explicit target/key, and `verify-installed-service.ps1`.
- Produces: Schema 1 `real_service_acceptance_verified` after installed verification, generated-veth service acceptance, exact rollback, stable network/eBPF comparison, and zero generated residue.

- [x] **Step 1: Preserve the reviewed combined transaction under the Gate 2 name**

Create `scripts/verify-real-service-acceptance.ps1` from the combined controller at commit `d75a43980c0c0d8cbbfecf4f5238eb3a59ff6fc2`. Preserve its bounded process runner, exact artifact/checksum verification, strict authorization parser, embedded remote phases, stable state snapshots, cancellation cleanup, plan/apply/installed/service/rollback ordering, and prohibited-operation surface.

The public parameters remain:

```powershell
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $Commit,
    [Parameter(Mandatory)] [string] $InstallAuthorizationPath,
    [Parameter(Mandatory)] [string] $RollbackAuthorizationPath,
    [Parameter(Mandatory)] [string] $ServiceAuthorizationPath,
    [Parameter(Mandatory)] [string] $DeploymentAuthorizationPath,
    [Parameter(Mandatory)] [string] $PerformanceEvidencePath,
    [ValidateRange(120, 1800)] [int] $TimeoutSeconds = 900
)
```

- [x] **Step 2: Give Gate 2 a distinct decision and truthful cleanup field**

Require the inner report before rollback:

```powershell
$ServiceVerification = & $ServiceHarness -Commit $Commit -RunId $ServiceRunId -ServiceAuthorizationPath $ServiceAuthorizationPath -InstallTransactionId $TransactionId -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 900)) | ConvertFrom-Json
if ([string]$ServiceVerification.decision -cne 'service_verified' -or
    -not [bool]$ServiceVerification.owned_cleanup_complete) {
    throw 'separate service acceptance did not complete exact cleanup'
}
```

Replace the former combined report decision and add explicit cleanup propagation:

```powershell
decision = 'real_service_acceptance_verified'
service_decision = [string]$ServiceVerification.decision
owned_cleanup_complete = [bool]$ServiceVerification.owned_cleanup_complete
```

Keep `install_transaction_id`, `install_decision`, `installed_check_decision`, `rollback_decision`, workflow/artifact identity, before/after network and eBPF hashes, `outside_install_state_unchanged = $true`, `generated_residue_count = 0`, and `mutations_performed = $true`.

- [x] **Step 3: Record RED evidence and push GREEN**

```powershell
git diff --check
git add -- scripts/verify-real-service-acceptance.ps1 docs/superpowers/plans/2026-08-17-separate-real-node-acceptance-gates.md
git commit -m "feat: add separate real service acceptance gate"
git push origin main
```

- [x] **Step 4: Require all five GitHub jobs**

Use the exact commit with `gh run list` and `gh run watch`. Require five successful jobs and the exact ten-file/nine-checksum artifact. Do not download or execute the controller on a node. Record the exact GREEN evidence in this plan.

**Task 4 GREEN evidence:** Commit `8f526c8f79bb83bc6f2391aa19c2f81954d58eb0`, GitHub run `32011451181`. Userspace, eBPF, Script safety, Windows PowerShell safety, and Bundle all succeeded. The Gate 2 source is byte-equivalent to the previously reviewed combined controller at `d75a43980c0c0d8cbbfecf4f5238eb3a59ff6fc2` except for the distinct `real_service_acceptance_verified` decision and explicit `owned_cleanup_complete` propagation. No real-node command ran.

---

### Task 5: Correct documentation and complete the G.1.1 safety audit

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `docs/l2-loop-agent-design.md`
- Modify: `docs/superpowers/specs/2026-08-14-single-interface-read-only-canary-preparation-design.md`
- Modify: `docs/superpowers/plans/2026-08-14-single-interface-read-only-canary-preparation.md`
- Modify: `docs/superpowers/specs/2026-08-17-separate-real-node-acceptance-gates-design.md`
- Modify: `docs/superpowers/plans/2026-08-17-separate-real-node-acceptance-gates.md`
- Modify focused tests/scripts only if the audit first adds a reproducing RED test.

**Interfaces:**
- Consumes: final Gate 1 and Gate 2 scripts plus exact GitHub evidence.
- Produces: consistent operator commands, completion evidence, and an explicit stop before Gate 1 real-node authorization.

- [x] **Step 1: Audit the two controller surfaces**

Trace and record:

```text
Gate 1 CLI parameters -> artifact/auth validation -> plan -> apply -> installed -> rollback -> identity comparison -> report
Gate 2 CLI parameters -> fresh artifact/auth validation -> plan -> apply -> installed -> inner generated-veth service -> rollback -> identity comparison -> report
```

Search for regressions:

```powershell
rg -n "ServiceAuthorizationPath|ServiceHarness|service_decision|verify-installed-service" scripts/verify-real-install.ps1
rg -n "Interface|default route|systemctl (enable|disable|restart)|rm -r|Remove-Item.*-Recurse|bpftool.*(detach|delete)|physical_canary_ready" scripts/verify-real-install.ps1 scripts/verify-real-service-acceptance.ps1
```

Expected: the first command returns no match; the second returns no prohibited execution surface. If a defect is found, add a focused failing static test, prove RED in GitHub, apply the minimum fix, and prove all five jobs GREEN before continuing.

- [x] **Step 2: Correct operator documentation**

Document these exact invocations separately:

```powershell
$ExactGreenCommit = git rev-parse HEAD
$Gate1InstallAuthorizationPath = 'D:\l2-loop-authorizations\gate1-install.json'
$Gate1RollbackAuthorizationPath = 'D:\l2-loop-authorizations\gate1-rollback.json'
$DeploymentAuthorizationPath = 'D:\l2-loop-authorizations\deployment.json'
$PerformanceEvidencePath = 'D:\l2-loop-authorizations\performance.json'
pwsh -NoProfile -File scripts/verify-real-install.ps1 `
    -Commit $ExactGreenCommit `
    -InstallAuthorizationPath $Gate1InstallAuthorizationPath `
    -RollbackAuthorizationPath $Gate1RollbackAuthorizationPath `
    -DeploymentAuthorizationPath $DeploymentAuthorizationPath `
    -PerformanceEvidencePath $PerformanceEvidencePath
```

```powershell
$Gate2InstallAuthorizationPath = 'D:\l2-loop-authorizations\gate2-install.json'
$Gate2RollbackAuthorizationPath = 'D:\l2-loop-authorizations\gate2-rollback.json'
$Gate2ServiceAuthorizationPath = 'D:\l2-loop-authorizations\gate2-service.json'
pwsh -NoProfile -File scripts/verify-real-service-acceptance.ps1 `
    -Commit $ExactGreenCommit `
    -InstallAuthorizationPath $Gate2InstallAuthorizationPath `
    -RollbackAuthorizationPath $Gate2RollbackAuthorizationPath `
    -ServiceAuthorizationPath $Gate2ServiceAuthorizationPath `
    -DeploymentAuthorizationPath $DeploymentAuthorizationPath `
    -PerformanceEvidencePath $PerformanceEvidencePath
```

State that Gate 2 repeats installation under new authorization and never inherits Gate 1 state. Preserve the four-stage order and explicitly state that no real-node gate was executed during G.1.1 development.

- [x] **Step 3: Mark the correction in the original G.1 records**

Add a dated correction note to the original G.1 design and plan: Task 9’s single combined controller was superseded by G.1.1 because distinct authorization documents were insufficient to provide distinct operator execution gates. Do not rewrite historical RED/GREEN evidence.

- [x] **Step 4: Push final documentation and require exact-SHA GREEN**

```powershell
git diff --check
git add -- README.md docs/development.md docs/l2-loop-agent-design.md docs/superpowers/specs/2026-08-14-single-interface-read-only-canary-preparation-design.md docs/superpowers/plans/2026-08-14-single-interface-read-only-canary-preparation.md docs/superpowers/specs/2026-08-17-separate-real-node-acceptance-gates-design.md docs/superpowers/plans/2026-08-17-separate-real-node-acceptance-gates.md
git commit -m "docs: complete independent acceptance gate audit"
git push origin main
```

Require Userspace, eBPF, Script safety, Windows PowerShell safety, and Bundle success for the exact final commit. Verify the artifact inventory has ten files with nine checksum-covered payloads.

- [x] **Step 5: Stop for Gate 1 authorization**

Verify and report:

```powershell
$Head = git rev-parse HEAD
$Remote = git ls-remote origin refs/heads/main | ForEach-Object { ($_ -split "`t")[0] }
git status --porcelain
```

Expected: `HEAD == origin/main`, no worktree output, five green jobs, exact artifact available, and no node/systemd/network/eBPF operation performed. Request one exact host and a task-scoped Gate 1 authorization only. Do not request or execute Gate 2, Gate 3, or Gate 4 authorization at this checkpoint.

**Task 5 GREEN evidence:** Commit `e4aa9a80046ddccfcd3ae6c9ea6ffb5f881fb8dd`, GitHub run `32012460638`. Userspace, eBPF, Script safety, Windows PowerShell safety, and Bundle all succeeded. The exact artifact `l2-loop-linux-x86_64-e4aa9a80046ddccfcd3ae6c9ea6ffb5f881fb8dd` is available. Before this completion-record commit, local `HEAD`, remote `main`, and the run head were identical and the worktree was clean. No node, systemd, journald, network-interface, physical-interface, or live eBPF operation ran during G.1.1. The next permitted action is a separately authorized Gate 1 request only.

## Execution Checkpoints

- Every RED commit records the exact SHA, workflow run, failing jobs, and failure text proving the new assertion is active.
- Every GREEN commit requires all five GitHub jobs for the exact SHA before the next task begins.
- No local Rust or PowerShell test substitutes for GitHub evidence.
- No real-node connection occurs during Tasks 1–5.
- Any unexpected failure, authorization ambiguity, identity disagreement, or design conflict stops execution rather than widening scope.
