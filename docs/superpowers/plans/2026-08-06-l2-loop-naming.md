# L2 Loop Detection Agent Naming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the retired product identifier from every tracked path and file, establish the canonical L2 naming contract, and consolidate development on `main`.

**Architecture:** A repository-level regression test scans the exact set returned by `git ls-files`, checking both path names and file contents case-insensitively. After proving the guard fails against the legacy tree in GitHub Actions, the workspace, Rust identifiers, command names, eBPF symbols, runtime paths, and documentation are renamed as one atomic contract change.

**Tech Stack:** Rust 2024 workspace, Aya/eBPF, Clap, GitHub Actions, PowerShell and Git.

## Global Constraints

- The public names are `二层环路检测 Agent` and `L2 Loop Detection Agent`.
- Technical identifiers use the `l2-loop` or `l2_loop` stem.
- The control command is `l2-loopctl`; the daemon command is `l2-loopd`.
- Every tracked path and file must be free of the retired four-letter identifier, case-insensitively.
- Historical private conversation archives remain untracked and must not be pushed.
- Compilation, formatting, linting, tests, and eBPF builds run only in GitHub Actions.
- Commits are pushed directly to `main`.

---

### Task 1: Add the repository naming guard

**Files:**
- Create: `xtask/tests/public_naming.rs`

**Interfaces:**
- Consumes: the NUL-delimited tracked-file list from `git ls-files -z`
- Produces: `tracked_repository_is_free_of_retired_identifier()`

- [ ] **Step 1: Write the failing test**

```rust
use std::{fs, path::Path, process::Command};

#[test]
fn tracked_repository_is_free_of_retired_identifier() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live below the repository root");
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository)
        .output()
        .expect("git must be available in CI");
    assert!(output.status.success(), "git ls-files failed");

    let forbidden = String::from_utf8(vec![99, 115, 109, 112])
        .expect("the retired identifier bytes are valid UTF-8");
    let mut matches = Vec::new();

    for raw_path in output.stdout.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let relative = String::from_utf8_lossy(raw_path);
        let path = repository.join(relative.as_ref());
        if relative.to_ascii_lowercase().contains(&forbidden) {
            matches.push(format!("path: {relative}"));
        }

        let contents = fs::read(&path).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", path.display())
        });
        if String::from_utf8_lossy(&contents)
            .to_ascii_lowercase()
            .contains(&forbidden)
        {
            matches.push(format!("content: {relative}"));
        }
    }

    assert!(
        matches.is_empty(),
        "retired identifier found in tracked repository:\n{}",
        matches.join("\n")
    );
}
```

- [ ] **Step 2: Commit and push the red test to GitHub**

```text
git add xtask/tests/public_naming.rs
git commit -m "test: forbid retired project identifier"
git push origin main
```

Expected: the GitHub Actions `Userspace` job fails in `cargo test`, listing existing legacy paths and contents. The eBPF job may remain green.

### Task 2: Rename the Rust workspace and executable contract

**Files:**
- Create through rename: `crates/l2-loop-common/**`
- Create through rename: `crates/l2-loop-core/**`
- Create through rename: `crates/l2-loop-agent/**`
- Create through rename: `crates/l2-loop-cli/**`
- Create through rename: `ebpf/l2-loop-ebpf/**`
- Modify: `Cargo.toml`
- Modify: `xtask/src/main.rs`
- Modify: `xtask/tests/public_ebpf_contract.rs`
- Modify: every Rust source and test importing a workspace crate

**Interfaces:**
- Consumes: existing ABI structs, domain types, service ports, CLI grammar, and fail-open eBPF behavior
- Produces: crates with the `l2-loop-*` package stem, Rust imports with the `l2_loop_*` stem, `l2-loopctl`, `l2-loopd`, and four `l2_loop_*` eBPF entry points

- [ ] **Step 1: Rename tracked directories with Git**

```powershell
$retired = -join ([char[]](99, 115, 109, 112))
git mv "crates/$retired-loop-common" crates/l2-loop-common
git mv "crates/$retired-loop-core" crates/l2-loop-core
git mv "crates/$retired-loop-agent" crates/l2-loop-agent
git mv "crates/$retired-loop-cli" crates/l2-loop-cli
git mv "ebpf/$retired-loop-ebpf" ebpf/l2-loop-ebpf
```

- [ ] **Step 2: Apply the exact identifier mapping to tracked text files**

```powershell
$retiredLower = -join ([char[]](99, 115, 109, 112))
$retiredUpper = $retiredLower.ToUpperInvariant()
$files = git grep -Il ''
foreach ($file in $files) {
    $path = Join-Path (Get-Location) $file
    $text = [IO.File]::ReadAllText($path)
    $text = $text.Replace("$retiredUpper Loop Agent", 'L2 Loop Detection Agent')
    $text = $text.Replace("$retiredUpper Loop", 'L2 Loop')
    $text = $text.Replace("$retiredLower-loop", 'l2-loop')
    $text = $text.Replace("${retiredLower}_loop", 'l2_loop')
    $text = $text.Replace("${retiredLower}_", 'l2_loop_')
    $text = $text.Replace($retiredUpper, 'L2')
    [IO.File]::WriteAllText($path, $text)
}
```

- [ ] **Step 3: Make executable and eBPF names explicit**

Add this binary target to `crates/l2-loop-agent/Cargo.toml`:

```toml
[[bin]]
name = "l2-loopd"
path = "src/main.rs"
```

Ensure `crates/l2-loop-cli/Cargo.toml` contains:

```toml
[[bin]]
name = "l2-loopctl"
path = "src/main.rs"
```

Ensure `xtask/tests/public_ebpf_contract.rs` asserts these symbols:

```rust
for program in [
    "l2_loop_xdp_ingress",
    "l2_loop_tc_egress",
    "l2_loop_tc_path_ingress",
    "l2_loop_tc_path_egress",
] {
    assert!(PROGRAM_SOURCE.contains(program));
}
```

- [ ] **Step 4: Commit the executable rename**

```text
git add Cargo.toml crates ebpf xtask
git commit -m "refactor: rename loop detection workspace"
```

### Task 3: Rename product documentation and operating paths

**Files:**
- Modify: `README.md`
- Create through rename: `docs/l2-loop-agent-design.md`
- Create through rename: `docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md`
- Create through rename: `docs/superpowers/plans/2026-08-06-l2-loop-rust-foundation.md`
- Modify: `docs/development.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the canonical names and paths in `docs/superpowers/specs/2026-08-06-l2-loop-naming-design.md`
- Produces: public documentation with a single product identity and CI triggered by `main` and pull requests

- [ ] **Step 1: Rename the three legacy documentation paths**

```powershell
$retired = -join ([char[]](99, 115, 109, 112))
git mv "docs/$retired-physical-loop-agent-design.md" docs/l2-loop-agent-design.md
git mv "docs/superpowers/specs/2026-08-06-$retired-loop-rust-foundation-design.md" docs/superpowers/specs/2026-08-06-l2-loop-rust-foundation-design.md
git mv "docs/superpowers/plans/2026-08-06-$retired-loop-rust-foundation.md" docs/superpowers/plans/2026-08-06-l2-loop-rust-foundation.md
```

- [ ] **Step 2: Normalize public copy and runtime paths**

Set the README heading to:

```markdown
# 二层环路检测 Agent
```

Use `L2 Loop Detection Agent` for English prose. Replace all runtime paths with `/etc/l2-loop`, `/run/l2-loop`, `/var/lib/l2-loop`, and `/sys/fs/bpf/l2-loop`. Update every relative documentation link to its renamed target.

- [ ] **Step 3: Record the direct-main workflow**

In `.github/workflows/ci.yml`, keep `push.branches` limited to:

```yaml
branches:
  - main
```

In `docs/development.md`, state that this single-developer repository commits directly to `main` and that all compilation remains in GitHub Actions.

- [ ] **Step 4: Verify the static naming contract without compiling locally**

```powershell
$retired = -join ([char[]](99, 115, 109, 112))
$hits = git grep -in $retired
$paths = git ls-files | Select-String -Pattern $retired -CaseSensitive:$false
if ($hits -or $paths) { throw 'retired identifier remains in tracked repository' }
```

Expected: no output and exit code 0.

- [ ] **Step 5: Commit and push the green implementation**

```text
git add .github README.md docs crates ebpf xtask Cargo.toml
git commit -m "docs: adopt L2 loop detection identity"
git push origin main
```

Expected: GitHub Actions `Userspace` and `eBPF` jobs both pass for the new `main` commit.

### Task 4: Retire the merged branch workflow

**Files:**
- No tracked file changes beyond Task 3

**Interfaces:**
- Consumes: a green `main` commit containing all former development-branch commits
- Produces: one active development branch, `main`, with no open legacy pull request

- [ ] **Step 1: Confirm the former branch is merged**

```text
git merge-base --is-ancestor agent/rust-foundation main
```

Expected: exit code 0.

- [ ] **Step 2: Remove the linked worktree and merged branch references**

```text
git worktree remove .worktrees/rust-foundation
git branch -d agent/rust-foundation
git push origin --delete agent/rust-foundation
```

- [ ] **Step 3: Close any obsolete pull request and verify GitHub state**

```text
gh pr list --state open
gh run list --branch main --limit 3
git status -sb
```

Expected: no obsolete open pull request, the latest `main` workflow is successful, and the local tree is clean and aligned with `origin/main`.

