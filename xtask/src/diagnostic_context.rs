//! Fixed generated-veth context. No network mutations or BPF operations.
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use nix::libc;
use serde_json::Value;

use crate::{
    diagnostic::lower_hex,
    diagnostic_session::{DiagnosticRequest, validate_request},
};

pub(crate) fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> Result<T, String> {
    result.map_err(|error| format!("DX_RUNTIME: {error:?}"))
}

pub(crate) fn require(value: bool, reason: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(format!("DX_CONTEXT: {reason}")) }
}

pub(crate) fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

pub(crate) fn private_ancestors(path: &Path) -> Result<(), String> {
    require(path.is_absolute(), "absolute path required")?;
    require(checked(fs::canonicalize(path))? == path, "symlink or noncanonical path")?;
    for part in path.ancestors() {
        let metadata = checked(fs::symlink_metadata(part))?;
        require(!metadata.file_type().is_symlink() && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0, "unsafe path ownership or permissions")?;
    }
    Ok(())
}

pub(crate) fn read_private(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    private_ancestors(path)?;
    let mut file = checked(OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path))?;
    let before = checked(file.metadata())?;
    require(before.is_file() && before.nlink() == 1 && before.len() <= max,
        "bounded single-link regular input required")?;
    let mut bytes = Vec::new();
    checked((&mut file).take(max + 1).read_to_end(&mut bytes))?;
    let after = checked(file.metadata())?;
    require(identity(&before) == identity(&after) && before.len() == after.len()
        && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
        && after.len() == bytes.len() as u64 && bytes.len() as u64 <= max,
        "input changed during read")?;
    Ok(bytes)
}

pub(crate) struct DiagnosticContext {
    pub request: DiagnosticRequest,
    pub root: PathBuf,
    pub host: String,
    pub peer: String,
    pub namespace: String,
    root_identity: (u64, u64),
    namespace_file: File,
}

impl DiagnosticContext {
    pub fn open(run_id: &str) -> Result<Self, String> {
        require(lower_hex(run_id, 32), "invalid run ID")?;
        require(nix::unistd::geteuid().is_root(), "root required")?;
        let root = Path::new("/run/l2-loop/accept").join(run_id);
        private_ancestors(&root)?;
        let root_metadata = checked(fs::symlink_metadata(&root))?;
        require(root_metadata.is_dir() && root_metadata.mode() & 0o777 == 0o700,
            "private generated root required")?;
        let bytes = read_private(&root.join("diagnostic-request.json"), 65_536)?;
        let request = checked(validate_request(&bytes))?;
        require(request.run_id == run_id, "request/run mismatch")?;
        let namespace = format!("l2ns-{}", &run_id[..12]);
        let namespace_path = Path::new("/run/netns").join(&namespace);
        private_ancestors(&namespace_path)?;
        let namespace_file = checked(OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW).open(namespace_path))?;
        let context = Self {
            request, root, host: format!("l2h{}", &run_id[..10]),
            peer: format!("l2n{}", &run_id[..10]), namespace,
            root_identity: identity(&root_metadata), namespace_file,
        };
        context.verify(true)?;
        Ok(context)
    }

    pub fn verify_root(&self) -> Result<(), String> {
        private_ancestors(&self.root)?;
        let metadata = checked(fs::symlink_metadata(&self.root))?;
        require(identity(&metadata) == self.root_identity && metadata.mode() & 0o777 == 0o700,
            "generated root identity changed")
    }

    pub fn verify(&self, down: bool) -> Result<(), String> {
        self.verify_root()?;
        let expected = (self.request.namespace_device, self.request.namespace_inode);
        let ns_path = Path::new("/run/netns").join(&self.namespace);
        private_ancestors(&ns_path)?;
        require(identity(&checked(fs::metadata(&ns_path))?) == expected
            && identity(&checked(self.namespace_file.metadata())?) == expected,
            "generated namespace identity changed")?;
        let current = identity(&checked(fs::metadata("/proc/self/ns/net"))?);
        require(current == identity(&checked(fs::metadata("/proc/1/ns/net"))?)
            && current != expected, "initial network namespace required")?;
        let hosts = ip(&["-j", "-d", "address", "show", "dev", &self.host])?;
        let peers = ip(&["-n", &self.namespace, "-j", "-d", "address", "show"])?;
        let hosts = hosts.as_array().ok_or("DX_CONTEXT: invalid host snapshot")?;
        let peers = peers.as_array().ok_or("DX_CONTEXT: invalid peer snapshot")?;
        require(hosts.len() == 1 && peers.len() == 2
            && peers.iter().filter(|p| p["ifname"] == "lo").count() == 1,
            "namespace is not a dedicated pair")?;
        let peer = peers.iter().find(|p| p["ifname"] == self.peer)
            .ok_or("DX_CONTEXT: peer absent")?;
        validate_link(&hosts[0], &self.host, self.request.ifindex,
            self.request.peer_ifindex, &self.request.host_mac, down)?;
        validate_link(peer, &self.peer, self.request.peer_ifindex,
            self.request.ifindex, &self.request.peer_mac, down)
    }
}

fn ip(args: &[&str]) -> Result<Value, String> {
    let output = checked(Command::new("timeout").args(["--signal=KILL", "3", "ip"])
        .args(args).output())?;
    require(output.status.success() && output.stdout.len() <= 65_536,
        "bounded ip inspection failed")?;
    checked(serde_json::from_slice(&output.stdout))
}

fn validate_link(link: &Value, name: &str, index: u32, peer: u32, mac: &str,
    down: bool) -> Result<(), String> {
    let flags = link["flags"].as_array().ok_or("DX_CONTEXT: missing link flags")?;
    let addresses = link["addr_info"].as_array().ok_or("DX_CONTEXT: missing addresses")?;
    require(link["ifname"] == name && link["ifindex"] == index
        && link["link_index"] == peer && link["address"] == mac
        && link["linkinfo"]["info_kind"] == "veth" && link.get("master").is_none()
        && addresses.is_empty() && (!down || !flags.iter().any(|f| f == "UP")),
        "generated veth identity, address or topology mismatch")
}
