//! Separate acceptance-only executable runtime; never linked by the product daemon.
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{fd::{AsFd, AsRawFd}, unix::fs::{MetadataExt, OpenOptionsExt}},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use aya::{Ebpf, maps::{HashMap, Map, PerCpuHashMap, PerCpuValues}, programs::{SchedClassifier, Xdp}};
use l2_loop_agent::{SafeXdpPort, SafeTcPort,
    linux::{xdp::{RtnetlinkXdpIo, SafeXdp, LoadedXdp, XdpIo, XdpInventory},
        tc::{RtnetlinkTcIo, SafeTc, LoadedTc, TcIo, TcClsactState, TC_EGRESS_HANDLE, TC_PRIORITY_FIRST}},
    ownership::{OwnedXdp, OwnedTc, TcHook, XdpAttachMode},
};
use l2_loop_common::{CounterValue, InterfaceConfig, StatsKey, FINGERPRINT_SAMPLE_SHIFT,
    agent_mode, hook_role, vlan_visibility};
use nix::libc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{diagnostic::{DiagnosticProfile, lower_hex, verify_diagnostic_identity},
    diagnostic_context::{DiagnosticContext, checked, identity, read_private, require},
    diagnostic_elf::inspect_diagnostic_elf,
    diagnostic_session::{DiagnosticBackend, SessionStep, run_session},
};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn request_stop(_: libc::c_int) { STOP.store(true, Ordering::Relaxed); }

pub fn run(run_id: &str) -> Result<(), String> {
    STOP.store(false, Ordering::Relaxed);
    // SAFETY: the handlers only perform a lock-free atomic store and never unwind.
    unsafe {
        libc::signal(libc::SIGTERM, request_stop as libc::sighandler_t);
        libc::signal(libc::SIGINT, request_stop as libc::sighandler_t);
    }
    let context = DiagnosticContext::open(run_id)?;
    let mut runtime = Runtime { context, bpf: None, loaded_xdp: None, loaded_tc: None,
        xdp: None, tc: None, clsact_created: false, lease: None, lease_bytes: vec![],
        map_ids: BTreeMap::new(), stop_reason: "not_started", counters: Value::Null };
    run_session(&mut runtime).map_err(|error| format!("DX_SESSION: {error:?}"))
}

struct Runtime {
    context: DiagnosticContext,
    bpf: Option<Ebpf>,
    loaded_xdp: Option<LoadedXdp>,
    loaded_tc: Option<LoadedTc>,
    xdp: Option<OwnedXdp>,
    tc: Option<OwnedTc>,
    clsact_created: bool,
    lease: Option<File>,
    lease_bytes: Vec<u8>,
    map_ids: BTreeMap<String, u32>,
    stop_reason: &'static str,
    counters: Value,
}

impl Runtime {
    fn prepare(&mut self) -> Result<(), String> {
        self.context.verify(true)?;
        self.empty_hooks()?;
        let profile = self.context.request.profile;
        let (filename, xdp_name, tc_name) = profile.declaration();
        let object = self.context.root.join("object").join(filename);
        let manifest = self.context.root.join("object/diagnostic.json");
        let commit = option_env!("L2_DIAGNOSTIC_COMMIT").unwrap_or("");
        let digest = match profile {
            DiagnosticProfile::HooksOnly => option_env!("L2_DIAGNOSTIC_HOOKS"),
            DiagnosticProfile::ConfigLookup => option_env!("L2_DIAGNOSTIC_CONFIG"),
            DiagnosticProfile::Counters => option_env!("L2_DIAGNOSTIC_COUNTERS"),
            DiagnosticProfile::Fingerprints => option_env!("L2_DIAGNOSTIC_FULL"),
        }.unwrap_or("");
        require(lower_hex(commit, 40) && lower_hex(digest, 64), "compiled CI binding absent")?;
        // The exact in-memory bytes checked here are the bytes passed to Aya.
        let bytes = read_private(&object, 16 * 1024 * 1024)?;
        read_private(&manifest, 65_536)?;
        checked(verify_diagnostic_identity(&manifest, &object, commit, profile))?;
        require(format!("{:x}", Sha256::digest(&bytes)) == digest, "compiled object digest mismatch")?;
        checked(inspect_diagnostic_elf(&bytes, profile))?;
        let lease_path = self.context.root.join("diagnostic-lease.json");
        // O_EXCL is the per-run concurrency lock; existing or stale leases are never opened.
        self.lease = Some(checked(OpenOptions::new().write(true).read(true).create_new(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(lease_path))?);
        self.write_lease(json!({"state":"preparing","run_id":self.context.request.run_id}))?;
        let mut bpf = checked(Ebpf::load(&bytes))?;
        let xdp: &mut Xdp = checked(bpf.program_mut(xdp_name).ok_or("XDP absent")?.try_into())?;
        checked(xdp.load())?;
        let info = checked(xdp.info())?;
        self.loaded_xdp = Some(LoadedXdp { program_fd: checked(xdp.fd())?.as_fd().as_raw_fd(),
            program_id: info.id(), program_tag: info.tag().to_be_bytes() });
        let tc: &mut SchedClassifier = checked(bpf.program_mut(tc_name).ok_or("TC absent")?.try_into())?;
        checked(tc.load())?;
        self.loaded_tc = Some(LoadedTc { program_fd: checked(tc.fd())?.as_fd().as_raw_fd(),
            program_id: checked(tc.info())?.id() });
        for (name, map) in bpf.maps() {
            let data = match map {
                Map::HashMap(data) | Map::PerCpuHashMap(data) | Map::LruHashMap(data) => data,
                _ => return Err("DX_RUNTIME: unexpected loaded map".into()),
            };
            self.map_ids.insert(name.to_owned(), checked(data.info())?.id());
        }
        self.bpf = Some(bpf);
        self.write_lease(json!({"schema_version":1,"purpose":"isolated_layered_diagnostic",
            "deployment_gate_evidence":false,"commit_sha":commit,"object_sha256":digest,
            "request":self.context.request,"map_ids":self.map_ids,
            "xdp_program_id":self.loaded_xdp.unwrap().program_id,
            "xdp_program_tag":self.loaded_xdp.unwrap().program_tag,
            "tc_program_id":self.loaded_tc.unwrap().program_id,
            "tc_priority":TC_PRIORITY_FIRST,"tc_handle":TC_EGRESS_HANDLE}))
    }

    fn empty_hooks(&self) -> Result<(), String> {
        let index = self.context.request.ifindex;
        require(checked(RtnetlinkXdpIo.query(index))? == XdpInventory::empty(), "XDP not empty")?;
        let tc = checked(RtnetlinkTcIo.query(index))?;
        require(tc.clsact == TcClsactState::Absent && tc.filters.is_empty(), "TC not empty")
    }

    fn write_lease(&mut self, value: Value) -> Result<(), String> {
        self.context.verify_root()?;
        let bytes = checked(serde_json::to_vec(&value))?;
        let file = self.lease.as_mut().ok_or("DX_RUNTIME: lease absent")?;
        checked(file.seek(SeekFrom::Start(0)))?;
        checked(file.set_len(0))?;
        checked(file.write_all(&bytes))?;
        checked(file.sync_all())?;
        self.lease_bytes = bytes;
        Ok(())
    }

    fn activate(&mut self) -> Result<(), String> {
        self.context.verify(true)?;
        let index = self.context.request.ifindex;
        let bpf = self.bpf.as_mut().ok_or("DX_RUNTIME: object absent")?;
        let mut stats = checked(PerCpuHashMap::<_, StatsKey, CounterValue>::try_from(
            bpf.map_mut("HOOK_STATS").ok_or("DX_RUNTIME: stats absent")?))?;
        let cpus = checked(aya::util::nr_cpus())?;
        for role in [hook_role::EXTERNAL_XDP_INGRESS, hook_role::PHYSICAL_TC_EGRESS] {
            for key in StatsKey::observation_keys(1, index, role) {
                let values = checked(PerCpuValues::try_from(vec![CounterValue { packets: 0, bytes: 0 }; cpus]))?;
                checked(stats.insert(key, values, 1))?;
            }
        }
        let mut configs = checked(HashMap::<_, u32, InterfaceConfig>::try_from(
            bpf.map_mut("IFACE_CONFIG").ok_or("DX_RUNTIME: config absent")?))?;
        checked(configs.insert(index, InterfaceConfig::new(1, 0, index, agent_mode::OBSERVE,
            hook_role::EXTERNAL_XDP_INGRESS, vlan_visibility::UNKNOWN, FINGERPRINT_SAMPLE_SHIFT), 1))
    }

    fn emit(&self, state: &str) -> Result<(), String> {
        let report = json!({"state":state,"run_id":self.context.request.run_id,
            "profile":self.context.request.profile,"deployment_gate_evidence":false,
            "map_ids":self.map_ids,"stop_reason":self.stop_reason,"counters":self.counters});
        let mut output = std::io::stdout().lock();
        checked(serde_json::to_writer(&mut output, &report))?;
        checked(output.write_all(b"\n"))?;
        checked(output.flush())
    }

    fn observe(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(u64::from(self.context.request.duration_seconds));
        self.emit("ready")?;
        self.stop_reason = wait_control(deadline)?;
        self.context.verify(false)?;
        let bpf = self.bpf.as_ref().ok_or("DX_RUNTIME: object absent")?;
        let stats = checked(PerCpuHashMap::<_, StatsKey, CounterValue>::try_from(
            bpf.map("HOOK_STATS").ok_or("DX_RUNTIME: stats absent")?))?;
        let mut totals = Vec::new();
        for role in [hook_role::EXTERNAL_XDP_INGRESS, hook_role::PHYSICAL_TC_EGRESS] {
            let values = checked(stats.get(&StatsKey::total(1, self.context.request.ifindex, role), 0))?;
            let (mut packets, mut bytes) = (0_u64, 0_u64);
            for value in values.iter() {
                packets = packets.checked_add(value.packets).ok_or("DX_RUNTIME: counter overflow")?;
                bytes = bytes.checked_add(value.bytes).ok_or("DX_RUNTIME: counter overflow")?;
            }
            totals.push(json!({"role":role,"packets":packets,"bytes":bytes}));
        }
        self.counters = json!(totals);
        Ok(())
    }
}

impl DiagnosticBackend for Runtime {
    fn perform(&mut self, step: SessionStep) -> Result<(), String> {
        use SessionStep::*;
        match step {
            Prepare => self.prepare(),
            AttachXdp => {
                self.context.verify(true)?;
                self.empty_hooks()?;
                let loaded = self.loaded_xdp.ok_or("DX_RUNTIME: XDP absent")?;
                let owned = OwnedXdp { ifindex:self.context.request.ifindex,
                    mode:XdpAttachMode::Generic, program_id:loaded.program_id,
                    program_tag:loaded.program_tag, link_id:None };
                // Retain the expected identity even when post-attach verification fails.
                self.xdp = Some(owned);
                checked(SafeXdp::new(RtnetlinkXdpIo).attach_no_replace(owned.ifindex, owned.mode, loaded))?;
                Ok(())
            }
            AttachTc => {
                self.context.verify(true)?;
                let index = self.context.request.ifindex;
                let inventory = checked(RtnetlinkTcIo.query(index))?;
                require(inventory.clsact == TcClsactState::Absent && inventory.filters.is_empty(), "TC changed")?;
                checked(RtnetlinkTcIo.ensure_clsact_exclusive(index))?;
                self.clsact_created = true;
                let loaded = self.loaded_tc.ok_or("DX_RUNTIME: TC absent")?;
                let owned = OwnedTc { ifindex:index, hook:TcHook::Egress, priority:TC_PRIORITY_FIRST,
                    handle:TC_EGRESS_HANDLE, program_id:loaded.program_id, created_clsact:false };
                self.tc = Some(owned);
                checked(RtnetlinkTcIo.attach_exclusive(index, owned.hook, owned.priority, owned.handle, loaded.program_fd))
            }
            Verify => {
                self.context.verify(true)?;
                checked(SafeXdp::new(RtnetlinkXdpIo).verify_exact(&self.xdp.ok_or("DX_RUNTIME: XDP absent")?))?;
                checked(SafeTc::new(RtnetlinkTcIo).verify_exact(&self.tc.ok_or("DX_RUNTIME: TC absent")?))
            }
            Activate => self.activate(),
            Observe => self.observe(),
            DetachTc => {
                if self.tc.is_some() || self.clsact_created { self.context.verify(false)?; }
                if let Some(owned) = self.tc {
                    checked(SafeTc::new(RtnetlinkTcIo).detach_exact(&owned))?;
                    self.tc = None;
                }
                if self.clsact_created {
                    checked(RtnetlinkTcIo.remove_clsact_if_empty_exact(self.context.request.ifindex))?;
                    self.clsact_created = false;
                }
                Ok(())
            }
            DetachXdp => {
                if let Some(owned) = self.xdp {
                    self.context.verify(false)?;
                    checked(SafeXdp::new(RtnetlinkXdpIo).detach_exact(&owned))?;
                    self.xdp = None;
                }
                Ok(())
            }
            Release => {
                require(self.xdp.is_none() && self.tc.is_none() && !self.clsact_created,
                    "hooks retained; lease must be retained")?;
                // Never look up/delete Maps by global ID or pin. Drop only our own FDs.
                self.bpf = None;
                Ok(())
            }
            Finish => {
                if let Some(file) = &mut self.lease {
                    self.context.verify_root()?;
                    let path = self.context.root.join("diagnostic-lease.json");
                    let current = checked(fs::symlink_metadata(&path))?;
                    require(current.is_file() && current.nlink() == 1
                        && identity(&current) == identity(&checked(file.metadata())?), "lease identity changed")?;
                    checked(file.seek(SeekFrom::Start(0)))?;
                    let mut bytes = Vec::new();
                    checked(file.take(65_537).read_to_end(&mut bytes))?;
                    require(bytes == self.lease_bytes, "lease contents changed")?;
                    checked(fs::remove_file(path))?;
                    self.lease = None;
                    self.emit("cleaned")?;
                }
                Ok(())
            }
        }
    }
}

fn wait_control(deadline: Instant) -> Result<&'static str, String> {
    let mut command = Vec::new();
    loop {
        if STOP.load(Ordering::Relaxed) { return Ok("signal"); }
        if Instant::now() >= deadline { return Ok("deadline"); }
        let mut poll = libc::pollfd { fd:libc::STDIN_FILENO, events:libc::POLLIN, revents:0 };
        // SAFETY: poll receives one valid initialized descriptor; timeout is bounded.
        let ready = unsafe { libc::poll(&mut poll, 1, 100) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err("DX_CONTROL: poll failed".into());
        }
        if ready == 0 { continue; }
        if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("DX_CONTROL: invalid input descriptor".into());
        }
        let mut bytes = [0_u8; 6];
        // SAFETY: read writes at most the valid byte slice length; poll signaled input/EOF.
        let count = unsafe { libc::read(libc::STDIN_FILENO, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count == 0 { return if command.is_empty() { Ok("eof") } else { Err("DX_CONTROL: partial input".into()) }; }
        if count < 0 { return Err("DX_CONTROL: read failed".into()); }
        command.extend_from_slice(&bytes[..count as usize]);
        require(command.len() <= 5 && b"stop\n".starts_with(&command), "invalid control command")?;
        if command == b"stop\n" { return Ok("stop"); }
    }
}
