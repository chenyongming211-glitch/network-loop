#![cfg(target_os = "linux")]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use l2_loop_agent::{
    DeploymentFilesystem,
    linux::{
        deployment_fs::LinuxDeploymentFilesystem,
        deployment_unit::validate_service_unit,
    },
};
use l2_loop_core::DeploymentArtifactIdentityV1;

const EXPECTED_UNIT: &str = "[Unit]\n\
Description=L2 Loop Detection Agent\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=/usr/libexec/l2-loop/l2-loopd\n\
User=root\n\
Group=root\n\
RuntimeDirectory=l2-loop\n\
RuntimeDirectoryMode=0700\n\
UMask=0077\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
ProtectSystem=strict\n\
ProtectHome=yes\n\
PrivateDevices=yes\n\
ProtectKernelTunables=yes\n\
ProtectKernelModules=yes\n\
ProtectControlGroups=yes\n\
RestrictSUIDSGID=yes\n\
RestrictRealtime=yes\n\
LockPersonality=yes\n\
MemoryDenyWriteExecute=yes\n\
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE\n\
RestrictAddressFamilies=AF_UNIX AF_NETLINK\n\
ReadWritePaths=/run/l2-loop /var/lib/l2-loop/evidence/v1\n\
TimeoutStopSec=10s\n\
Restart=no\n";

#[test]
fn deterministic_asset_is_the_exact_valid_contract() {
    let asset = include_bytes!("../../../packaging/l2-loop.service");

    assert_eq!(asset, EXPECTED_UNIT.as_bytes());
    assert!(validate_service_unit(asset).unwrap().is_valid());
}

#[test]
fn every_required_identity_and_hardening_value_is_exact() {
    for (label, before, after) in [
        (
            "description",
            "Description=L2 Loop Detection Agent",
            "Description=Loop Agent",
        ),
        ("type", "Type=simple", "Type=notify"),
        (
            "exec",
            "ExecStart=/usr/libexec/l2-loop/l2-loopd",
            "ExecStart=/usr/bin/l2-loopd",
        ),
        ("user", "User=root", "User=l2-loop"),
        ("group", "Group=root", "Group=l2-loop"),
        (
            "runtime",
            "RuntimeDirectory=l2-loop",
            "RuntimeDirectory=l2-loop-other",
        ),
        (
            "runtime-mode",
            "RuntimeDirectoryMode=0700",
            "RuntimeDirectoryMode=0755",
        ),
        ("umask", "UMask=0077", "UMask=0022"),
        (
            "new-privileges",
            "NoNewPrivileges=yes",
            "NoNewPrivileges=no",
        ),
        ("private-tmp", "PrivateTmp=yes", "PrivateTmp=no"),
        (
            "protect-system",
            "ProtectSystem=strict",
            "ProtectSystem=full",
        ),
        ("protect-home", "ProtectHome=yes", "ProtectHome=read-only"),
        ("private-devices", "PrivateDevices=yes", "PrivateDevices=no"),
        (
            "kernel-tunables",
            "ProtectKernelTunables=yes",
            "ProtectKernelTunables=no",
        ),
        (
            "kernel-modules",
            "ProtectKernelModules=yes",
            "ProtectKernelModules=no",
        ),
        (
            "control-groups",
            "ProtectControlGroups=yes",
            "ProtectControlGroups=no",
        ),
        ("suid-sgid", "RestrictSUIDSGID=yes", "RestrictSUIDSGID=no"),
        ("realtime", "RestrictRealtime=yes", "RestrictRealtime=no"),
        ("personality", "LockPersonality=yes", "LockPersonality=no"),
        (
            "w-x",
            "MemoryDenyWriteExecute=yes",
            "MemoryDenyWriteExecute=no",
        ),
        ("stop-timeout", "TimeoutStopSec=10s", "TimeoutStopSec=30s"),
        ("restart", "Restart=no", "Restart=on-failure"),
    ] {
        assert_rejected(label, &EXPECTED_UNIT.replacen(before, after, 1));
    }
}

#[test]
fn capability_and_address_family_sets_are_exact_and_ordered() {
    for (label, before, after) in [
        (
            "missing-capability",
            "CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE",
            "CAP_BPF CAP_NET_ADMIN CAP_PERFMON",
        ),
        (
            "added-capability",
            "CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE",
            "CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_ADMIN",
        ),
        (
            "reordered-capability",
            "CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE",
            "CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE",
        ),
        ("missing-family", "AF_UNIX AF_NETLINK", "AF_UNIX"),
        (
            "added-family",
            "AF_UNIX AF_NETLINK",
            "AF_UNIX AF_NETLINK AF_INET",
        ),
        (
            "reordered-family",
            "AF_UNIX AF_NETLINK",
            "AF_NETLINK AF_UNIX",
        ),
    ] {
        assert_rejected(label, &EXPECTED_UNIT.replacen(before, after, 1));
    }
}

#[test]
fn writable_paths_are_exact_and_never_broadened() {
    for (label, replacement) in [
        ("etc", "/etc"),
        ("usr", "/usr"),
        ("var", "/var"),
        ("sys", "/sys"),
        ("proc", "/proc"),
        ("runtime-only", "/run/l2-loop"),
        ("evidence-parent", "/run/l2-loop /var/lib/l2-loop"),
        ("reordered", "/var/lib/l2-loop/evidence/v1 /run/l2-loop"),
        ("relative", "run/l2-loop var/lib/l2-loop/evidence/v1"),
    ] {
        assert_rejected(
            label,
            &EXPECTED_UNIT.replacen("/run/l2-loop /var/lib/l2-loop/evidence/v1", replacement, 1),
        );
    }
}

#[test]
fn duplicate_unknown_and_execution_bearing_directives_are_rejected() {
    for (label, directive) in [
        ("duplicate", "Restart=no"),
        ("conflict", "Restart=always"),
        ("pre", "ExecStartPre=/usr/bin/true"),
        ("post", "ExecStartPost=/usr/bin/true"),
        ("stop", "ExecStop=/usr/bin/true"),
        ("reload", "ExecReload=/usr/bin/true"),
        ("root-directory", "RootDirectory=/tmp/root"),
        ("bind-path", "BindPaths=/tmp:/run/l2-loop"),
        ("environment", "Environment=LD_PRELOAD=/tmp/foreign.so"),
        ("unknown", "PermissionsStartOnly=yes"),
    ] {
        let changed = EXPECTED_UNIT.replacen("Restart=no", &format!("Restart=no\n{directive}"), 1);
        assert_rejected(label, &changed);
    }
}

#[test]
fn shell_expansion_continuation_and_noncanonical_syntax_are_rejected() {
    for (label, exec) in [
        ("shell", "/bin/sh -c /usr/libexec/l2-loop/l2-loopd"),
        ("semicolon", "/usr/libexec/l2-loop/l2-loopd;/usr/bin/true"),
        ("pipe", "/usr/libexec/l2-loop/l2-loopd|/usr/bin/true"),
        ("ampersand", "/usr/libexec/l2-loop/l2-loopd&"),
        ("specifier", "/usr/libexec/l2-loop/l2-loopd-%i"),
        ("variable", "/usr/libexec/l2-loop/$DAEMON"),
        ("braced-variable", "/usr/libexec/l2-loop/${DAEMON}"),
        ("relative", "l2-loopd"),
    ] {
        assert_rejected(
            label,
            &EXPECTED_UNIT.replacen("/usr/libexec/l2-loop/l2-loopd", exec, 1),
        );
    }

    for (label, changed) in [
        ("crlf", EXPECTED_UNIT.replace('\n', "\r\n")),
        (
            "continuation",
            EXPECTED_UNIT.replacen("Restart=no", "Restart=\\\nno", 1),
        ),
        (
            "leading-space",
            EXPECTED_UNIT.replacen("Restart=no", " Restart=no", 1),
        ),
        (
            "tab",
            EXPECTED_UNIT.replacen("Restart=no", "Restart\t=no", 1),
        ),
        (
            "comment",
            EXPECTED_UNIT.replacen("[Service]", "# comment\n[Service]", 1),
        ),
        (
            "install",
            format!("{EXPECTED_UNIT}\n[Install]\nWantedBy=multi-user.target\n"),
        ),
    ] {
        assert_rejected(label, &changed);
    }
}

#[test]
fn installer_sysctl_module_and_offload_commands_are_rejected() {
    for (label, command) in [
        (
            "install",
            "/usr/bin/install -d /var/lib/l2-loop/evidence/v1",
        ),
        ("mkdir", "/usr/bin/mkdir -p /var/lib/l2-loop/evidence/v1"),
        ("sysctl", "/usr/sbin/sysctl -w net.core.bpf_jit_enable=1"),
        ("module", "/usr/sbin/modprobe cls_bpf"),
        ("offload", "/usr/sbin/ethtool -K eth0 gro off"),
    ] {
        let changed = EXPECTED_UNIT.replacen(
            "ExecStart=/usr/libexec/l2-loop/l2-loopd",
            &format!("ExecStartPre={command}\nExecStart=/usr/libexec/l2-loop/l2-loopd"),
            1,
        );
        assert_rejected(label, &changed);
    }
}

#[test]
fn input_is_bounded_utf8_and_parser_source_never_executes_or_writes() {
    let oversized = vec![b' '; 65_537];
    assert!(validate_service_unit(&oversized).is_err());
    assert!(validate_service_unit(&[0xff, 0xfe]).is_err());

    let source = include_str!("../src/linux/deployment_unit.rs");
    for prohibited in [
        "Command::new",
        "systemctl",
        "systemd-analyze",
        "create_dir",
        "remove_file",
        "remove_dir",
        "fs::write",
        "File::create",
        ".write(true)",
    ] {
        assert!(
            !source.contains(prohibited),
            "unsafe primitive present: {prohibited}"
        );
    }
}

#[test]
fn fixed_override_and_drop_in_paths_are_rejected_without_discovery() {
    for relative in [
        "etc/systemd/system/l2-loop.service",
        "run/systemd/system/l2-loop.service",
        "usr/local/lib/systemd/system/l2-loop.service",
        "etc/systemd/system/l2-loop.service.d",
        "run/systemd/system/l2-loop.service.d",
        "usr/lib/systemd/system/l2-loop.service.d",
        "usr/local/lib/systemd/system/l2-loop.service.d",
    ] {
        let root = ServiceTree::valid(relative.replace('/', "-"));
        let occupied = root.path().join(relative);
        if relative.ends_with(".d") {
            fs::create_dir_all(&occupied).unwrap();
        } else {
            fs::create_dir_all(occupied.parent().unwrap()).unwrap();
            fs::write(&occupied, EXPECTED_UNIT).unwrap();
        }
        let mut filesystem = LinuxDeploymentFilesystem::new(artifact()).unwrap();
        assert!(
            filesystem.inspect_staged_service(root.path()).is_err(),
            "accepted service override: {relative}"
        );
    }
}

fn assert_rejected(label: &str, unit: &str) {
    assert!(
        validate_service_unit(unit.as_bytes()).is_err(),
        "accepted invalid unit: {label}"
    );
}

fn artifact() -> DeploymentArtifactIdentityV1 {
    DeploymentArtifactIdentityV1::new(
        "0123456789abcdef0123456789abcdef01234567",
        "0.1.0",
    )
    .unwrap()
}

struct ServiceTree {
    root: PathBuf,
}

impl ServiceTree {
    fn valid(label: impl AsRef<str>) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "l2-loop-unit-{}-{}-{nonce}",
            std::process::id(),
            label.as_ref()
        ));
        let unit = root.join("usr/lib/systemd/system/l2-loop.service");
        fs::create_dir_all(unit.parent().unwrap()).unwrap();
        fs::write(unit, EXPECTED_UNIT).unwrap();
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for ServiceTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
