use std::{
    fs::{self, File},
    future::Future,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use futures_util::TryStreamExt;
use l2_loop_core::{
    AttachmentState, AttachmentTarget, BondInspection, BondMode, BpfInspection, Direction,
    HookRole, InterfaceInspection, InterfaceKind, InterfaceName, InterfaceRef, KernelInspection,
    MemlockInspection, PF_BOND_NO_ACTIVE_SLAVE, PF_INTERFACE_MISSING, PF_INTERFACE_UNSUPPORTED,
    PF_KERNEL_CAPABILITY, PF_LIVE_INTERFACE, PF_MEMLOCK_TOO_LOW, PF_PIN_ROOT_FOREIGN,
    PF_TC_HANDLE_COLLISION, PF_TC_STATE_UNKNOWN, PF_XDP_OCCUPIED, PF_XDP_STATE_UNKNOWN,
    PinRootState, PreflightFinding, PreflightReport, TcAttachment,
};
use rtnetlink::packet_route::{
    link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage, LinkXdp, State},
    tc::{TcAttribute, TcFilterBpfOption, TcMessage, TcOption},
};
use thiserror::Error;

use crate::{PlatformInspector, PortError};

use super::{
    bond::parse_bond_snapshot,
    bpf_inventory::{
        BtfSnapshot, PinRootSnapshot, bpffs_mounted_at_standard_path, classify_pin_root,
    },
    interface::{KernelLinkKind, LinkRecord, TunMode, classify_interface},
    limits::{artifact_architecture_matches, parse_memlock_limits},
    topology::{ovs_vsctl_args, parse_ovs_bridge_name},
};

const AGENT_PIN_ROOT: &str = "/sys/fs/bpf/l2-loop";
const REQUIRED_MEMLOCK_BYTES: u64 = 8 * 1024 * 1024;
const ARTIFACT_TARGET: &str = "x86_64-unknown-linux-musl";
const RESERVED_TC_INGRESS_HANDLE: u32 = 0x4c32_0001;
const RESERVED_TC_EGRESS_HANDLE: u32 = 0x4c32_0002;
const PF_OVS_DISCOVERY: &str = "PF_OVS_DISCOVERY";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct InspectorError {
    message: String,
}

impl InspectorError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFileSnapshot {
    pub architecture: String,
    pub release: String,
    pub mounts: String,
    pub limits: String,
    pub bpf_jit: bool,
    pub btf: BtfSnapshot,
    pub pin_root: PinRootSnapshot,
    pub bond: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedTcAttachment {
    pub attachment: TcAttachment,
    pub owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfQuerySnapshot {
    pub bpf_syscall: bool,
    pub relevant_objects_enumerable: bool,
    pub xdp_native: AttachmentState,
    pub xdp_generic: AttachmentState,
    pub tc_state_known: bool,
    pub tc_clsact: bool,
    pub tc_ingress: Vec<ObservedTcAttachment>,
    pub tc_egress: Vec<ObservedTcAttachment>,
}

pub trait LinkSource {
    fn read_links(&mut self) -> Result<Vec<LinkRecord>, InspectorError>;
}

pub trait FileSource {
    fn read_host_files(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<HostFileSnapshot, InspectorError>;
}

pub trait BpfQuery {
    fn query_bpf(&mut self, ifindexes: &[u32]) -> Result<BpfQuerySnapshot, InspectorError>;
}

pub trait CommandSource {
    fn query_ovs_bridge(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<Option<InterfaceName>, InspectorError>;
}

pub struct LinuxInspector<L, F, B, C> {
    links: L,
    files: F,
    bpf: B,
    commands: C,
}

impl<L, F, B, C> LinuxInspector<L, F, B, C> {
    pub fn new(links: L, files: F, bpf: B, commands: C) -> Self {
        Self {
            links,
            files,
            bpf,
            commands,
        }
    }
}

impl<L, F, B, C> PlatformInspector for LinuxInspector<L, F, B, C>
where
    L: LinkSource,
    F: FileSource,
    B: BpfQuery,
    C: CommandSource,
{
    fn inspect(&mut self, requested: &InterfaceName) -> Result<PreflightReport, PortError> {
        let links = self.links.read_links().map_err(adapter_error)?;
        let files = self
            .files
            .read_host_files(requested)
            .map_err(adapter_error)?;
        let mut findings = Vec::new();
        let interface =
            inspect_interface(requested, &links, &files, &mut self.commands, &mut findings);
        let mut ifindexes = interface
            .proposed_targets
            .iter()
            .map(|target| target.interface.ifindex)
            .filter(|ifindex| *ifindex != 0)
            .collect::<Vec<_>>();
        ifindexes.sort_unstable();
        ifindexes.dedup();
        let queried = self.bpf.query_bpf(&ifindexes).map_err(adapter_error)?;
        let (kernel, bpf) = inspect_host(&files, queried, &mut findings);

        Ok(PreflightReport::new(interface, kernel, bpf, findings))
    }
}

fn adapter_error(error: InspectorError) -> PortError {
    PortError::Adapter(error.to_string())
}

fn inspect_interface<C: CommandSource>(
    requested: &InterfaceName,
    links: &[LinkRecord],
    files: &HostFileSnapshot,
    commands: &mut C,
    findings: &mut Vec<PreflightFinding>,
) -> InterfaceInspection {
    let Some(link) = links.iter().find(|link| &link.name == requested) else {
        findings.push(PreflightFinding::blocker(
            PF_INTERFACE_MISSING,
            "requested interface does not exist",
        ));
        return missing_interface(requested);
    };

    if link.ifindex == 0 {
        findings.push(PreflightFinding::blocker(
            PF_INTERFACE_MISSING,
            "requested interface has no usable kernel index",
        ));
        return missing_interface(requested);
    }

    let kind = classify_interface(link);
    if kind == InterfaceKind::Unsupported {
        findings.push(PreflightFinding::blocker(
            PF_INTERFACE_UNSUPPORTED,
            "requested interface kind is unsupported",
        ));
    }

    let (mut master, ambiguous_master) = resolve_kernel_master(link, links);
    if ambiguous_master {
        findings.push(PreflightFinding::blocker(
            PF_INTERFACE_UNSUPPORTED,
            "interface master relationship is ambiguous",
        ));
    }

    if kind == InterfaceKind::OvsInternal {
        match commands.query_ovs_bridge(requested) {
            Ok(Some(name)) if master.is_none() => {
                let ifindex = links
                    .iter()
                    .find(|candidate| candidate.name == name)
                    .map_or(0, |candidate| candidate.ifindex);
                master = Some(InterfaceRef { name, ifindex });
            }
            Ok(_) => {}
            Err(_) => findings.push(PreflightFinding::warning(
                PF_OVS_DISCOVERY,
                "Open vSwitch bridge discovery was unavailable",
            )),
        }
    }

    let bond = if kind == InterfaceKind::Bond {
        match files
            .bond
            .as_deref()
            .map(|snapshot| parse_bond_snapshot(snapshot, links))
        {
            Some(Ok(bond)) => Some(bond),
            Some(Err(error)) => {
                let (code, message) = if error.blocker_code().is_some() {
                    (
                        PF_BOND_NO_ACTIVE_SLAVE,
                        "bond has no unambiguous active slave",
                    )
                } else {
                    (
                        PF_INTERFACE_UNSUPPORTED,
                        "bond snapshot is unsupported or inconsistent",
                    )
                };
                findings.push(PreflightFinding::blocker(code, message));
                Some(unresolved_bond())
            }
            None => {
                findings.push(PreflightFinding::blocker(
                    PF_BOND_NO_ACTIVE_SLAVE,
                    "bond state is unavailable",
                ));
                Some(unresolved_bond())
            }
        }
    } else {
        None
    };

    let target = match kind {
        InterfaceKind::Unsupported => None,
        InterfaceKind::Bond => bond.as_ref().and_then(|bond| bond.active_slave.clone()),
        _ => Some(InterfaceRef {
            name: link.name.clone(),
            ifindex: link.ifindex,
        }),
    };
    let target_live = target.as_ref().is_some_and(|target| {
        links.iter().any(|candidate| {
            candidate.ifindex == target.ifindex && (candidate.admin_up || candidate.oper_up)
        })
    });
    let proposed_targets = target.map_or_else(Vec::new, attachment_targets);
    let isolated = matches!(kind, InterfaceKind::Veth | InterfaceKind::Tap)
        && !link.admin_up
        && !link.oper_up
        && master.is_none();
    let live_shared = link.admin_up || link.oper_up || master.is_some() || target_live;
    if live_shared {
        findings.push(PreflightFinding::blocker(
            PF_LIVE_INTERFACE,
            "interface is live or shared",
        ));
    }

    InterfaceInspection {
        requested: InterfaceRef {
            name: link.name.clone(),
            ifindex: link.ifindex,
        },
        kind,
        admin_up: link.admin_up,
        oper_up: link.oper_up,
        master,
        bond,
        proposed_targets,
        isolated,
        live_shared,
    }
}

fn unresolved_bond() -> BondInspection {
    BondInspection {
        mode: BondMode::Unsupported,
        slaves: Vec::new(),
        active_slave: None,
    }
}

fn missing_interface(requested: &InterfaceName) -> InterfaceInspection {
    InterfaceInspection {
        requested: InterfaceRef {
            name: requested.clone(),
            ifindex: 0,
        },
        kind: InterfaceKind::Unsupported,
        admin_up: false,
        oper_up: false,
        master: None,
        bond: None,
        proposed_targets: Vec::new(),
        isolated: false,
        live_shared: false,
    }
}

fn resolve_kernel_master(link: &LinkRecord, links: &[LinkRecord]) -> (Option<InterfaceRef>, bool) {
    let Some(master_ifindex) = link.master_ifindex else {
        return (None, false);
    };
    let matches = links
        .iter()
        .filter(|candidate| candidate.ifindex == master_ifindex)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return (None, true);
    }
    let master = matches[0];
    (
        Some(InterfaceRef {
            name: master.name.clone(),
            ifindex: master.ifindex,
        }),
        false,
    )
}

fn attachment_targets(interface: InterfaceRef) -> Vec<AttachmentTarget> {
    vec![
        AttachmentTarget {
            interface: interface.clone(),
            role: HookRole::ExternalXdpIngress,
        },
        AttachmentTarget {
            interface,
            role: HookRole::PhysicalTcEgress,
        },
    ]
}

fn inspect_host(
    files: &HostFileSnapshot,
    queried: BpfQuerySnapshot,
    findings: &mut Vec<PreflightFinding>,
) -> (KernelInspection, BpfInspection) {
    let bpffs_mounted = bpffs_mounted_at_standard_path(&files.mounts);
    let pin_root = classify_pin_root(files.pin_root);
    let btf_readable = files.btf.is_readable();
    let limits = parse_memlock_limits(&files.limits).ok();
    let memlock = limits.map_or(
        MemlockInspection {
            soft_bytes: Some(0),
            hard_bytes: Some(0),
            required_bytes: REQUIRED_MEMLOCK_BYTES,
            can_raise: false,
        },
        |limits| MemlockInspection {
            soft_bytes: limits.soft_bytes,
            hard_bytes: limits.hard_bytes,
            required_bytes: REQUIRED_MEMLOCK_BYTES,
            can_raise: limits.can_raise_to(REQUIRED_MEMLOCK_BYTES),
        },
    );

    if matches!(queried.xdp_native, AttachmentState::Unknown)
        || matches!(queried.xdp_generic, AttachmentState::Unknown)
    {
        findings.push(PreflightFinding::blocker(
            PF_XDP_STATE_UNKNOWN,
            "XDP attachment state cannot be determined",
        ));
    }
    if matches!(queried.xdp_native, AttachmentState::Occupied { .. })
        || matches!(queried.xdp_generic, AttachmentState::Occupied { .. })
    {
        findings.push(PreflightFinding::blocker(
            PF_XDP_OCCUPIED,
            "an unowned XDP program occupies the target",
        ));
    }
    if !queried.tc_state_known {
        findings.push(PreflightFinding::blocker(
            PF_TC_STATE_UNKNOWN,
            "TC attachment state cannot be determined",
        ));
    }
    if has_tc_collision(&queried.tc_ingress, &queried.tc_egress) {
        findings.push(PreflightFinding::blocker(
            PF_TC_HANDLE_COLLISION,
            "a reserved TC handle is occupied by an unowned filter",
        ));
    }
    if pin_root == PinRootState::Foreign {
        findings.push(PreflightFinding::blocker(
            PF_PIN_ROOT_FOREIGN,
            "agent pin root exists without valid ownership",
        ));
    }

    let soft_too_low = matches!(memlock.soft_bytes, Some(soft) if soft < REQUIRED_MEMLOCK_BYTES);
    if soft_too_low && memlock.can_raise {
        findings.push(PreflightFinding::warning(
            PF_MEMLOCK_TOO_LOW,
            "memlock soft limit must be raised before attachment",
        ));
    } else if !memlock.can_raise {
        findings.push(PreflightFinding::blocker(
            PF_MEMLOCK_TOO_LOW,
            "memlock limit cannot satisfy the planned BPF allocation",
        ));
    }

    let kernel_capability_missing = !bpffs_mounted
        || !queried.relevant_objects_enumerable
        || !artifact_architecture_matches(&files.architecture, ARTIFACT_TARGET)
        || files.release.trim().is_empty()
        || !queried.bpf_syscall
        || !files.bpf_jit
        || !btf_readable
        || !queried.tc_clsact;
    if kernel_capability_missing {
        findings.push(PreflightFinding::blocker(
            PF_KERNEL_CAPABILITY,
            "a required Linux BPF or traffic-control capability is unavailable",
        ));
    }

    let kernel = KernelInspection {
        architecture: files.architecture.clone(),
        release: files.release.clone(),
        bpf_syscall: queried.bpf_syscall,
        bpf_jit: files.bpf_jit,
        btf_readable,
        tc_clsact: queried.tc_clsact,
    };
    let bpf = BpfInspection {
        bpffs_mounted,
        relevant_objects_enumerable: queried.relevant_objects_enumerable,
        pin_root,
        xdp_native: queried.xdp_native,
        xdp_generic: queried.xdp_generic,
        tc_ingress: queried
            .tc_ingress
            .into_iter()
            .map(|observed| observed.attachment)
            .collect(),
        tc_egress: queried
            .tc_egress
            .into_iter()
            .map(|observed| observed.attachment)
            .collect(),
        memlock,
    };

    (kernel, bpf)
}

fn has_tc_collision(ingress: &[ObservedTcAttachment], egress: &[ObservedTcAttachment]) -> bool {
    ingress
        .iter()
        .any(|observed| !observed.owned && observed.attachment.handle == RESERVED_TC_INGRESS_HANDLE)
        || egress.iter().any(|observed| {
            !observed.owned && observed.attachment.handle == RESERVED_TC_EGRESS_HANDLE
        })
}

#[derive(Debug, Default)]
pub struct SystemLinkSource;

impl LinkSource for SystemLinkSource {
    fn read_links(&mut self) -> Result<Vec<LinkRecord>, InspectorError> {
        run_async(|| async {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|_| InspectorError::new("failed to open Linux link query"))?;
            tokio::spawn(connection);
            let mut messages = handle.link().get().execute();
            let mut links = Vec::new();
            while let Some(message) = messages
                .try_next()
                .await
                .map_err(|_| InspectorError::new("failed to read Linux link state"))?
            {
                if let Some(link) = link_record(message) {
                    links.push(link);
                }
            }
            Ok(links)
        })
    }
}

fn link_record(message: LinkMessage) -> Option<LinkRecord> {
    let mut name = None;
    let mut kind = None;
    let mut master_ifindex = None;
    let mut oper_up = false;
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = InterfaceName::new(value).ok(),
            LinkAttribute::Controller(value) => master_ifindex = Some(*value),
            LinkAttribute::OperState(value) => oper_up = *value == State::Up,
            LinkAttribute::LinkInfo(info) => kind = kernel_link_kind(info),
            _ => {}
        }
    }
    let name = name?;
    let sysfs = PathBuf::from("/sys/class/net").join(name.as_str());
    let driver_present = fs::metadata(sysfs.join("device/driver")).is_ok();
    let tun_mode = (kind == Some(KernelLinkKind::Tun))
        .then(|| read_tun_mode(&sysfs.join("tun_flags")))
        .flatten();

    Some(LinkRecord {
        name,
        ifindex: message.header.index,
        kind,
        tun_mode,
        driver_present,
        master_ifindex,
        admin_up: message.header.flags.contains(LinkFlags::Up),
        oper_up,
    })
}

fn kernel_link_kind(info: &[LinkInfo]) -> Option<KernelLinkKind> {
    info.iter().find_map(|attribute| match attribute {
        LinkInfo::Kind(InfoKind::Bond) => Some(KernelLinkKind::Bond),
        LinkInfo::Kind(InfoKind::Veth) => Some(KernelLinkKind::Veth),
        LinkInfo::Kind(InfoKind::Bridge) => Some(KernelLinkKind::Bridge),
        LinkInfo::Kind(InfoKind::Tun) => Some(KernelLinkKind::Tun),
        LinkInfo::Kind(InfoKind::Other(kind)) if kind == "openvswitch" => {
            Some(KernelLinkKind::OpenVSwitch)
        }
        LinkInfo::Kind(kind) => Some(KernelLinkKind::Other(kind.to_string())),
        _ => None,
    })
}

fn read_tun_mode(path: &Path) -> Option<TunMode> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    let flags = match value.strip_prefix("0x") {
        Some(hexadecimal) => u32::from_str_radix(hexadecimal, 16).ok()?,
        None => value.parse().ok()?,
    };
    if flags & 0x0002 != 0 {
        Some(TunMode::Tap)
    } else if flags & 0x0001 != 0 {
        Some(TunMode::Tun)
    } else {
        None
    }
}

#[derive(Debug, Default)]
pub struct SystemFileSource;

impl FileSource for SystemFileSource {
    fn read_host_files(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<HostFileSnapshot, InspectorError> {
        let mounts = read_required("/proc/mounts", "failed to read mount state")?;
        let limits = read_required("/proc/self/limits", "failed to read process limits")?;
        let release = read_required(
            "/proc/sys/kernel/osrelease",
            "failed to read kernel release",
        )?
        .trim()
        .to_owned();
        let bpf_jit = fs::read_to_string("/proc/sys/net/core/bpf_jit_enable")
            .is_ok_and(|value| value.trim() != "0");
        let btf_path = Path::new("/sys/kernel/btf/vmlinux");
        let btf_metadata = fs::metadata(btf_path).ok();
        let btf = BtfSnapshot {
            exists: btf_metadata.is_some(),
            regular_file: btf_metadata.is_some_and(|metadata| metadata.is_file()),
            readable: File::open(btf_path).is_ok(),
        };
        let pin_root = read_pin_root(Path::new(AGENT_PIN_ROOT));
        let bond =
            fs::read_to_string(PathBuf::from("/proc/net/bonding").join(interface.as_str())).ok();

        Ok(HostFileSnapshot {
            architecture: std::env::consts::ARCH.into(),
            release,
            mounts,
            limits,
            bpf_jit,
            btf,
            pin_root,
            bond,
        })
    }
}

fn read_required(path: &str, message: &str) -> Result<String, InspectorError> {
    fs::read_to_string(path).map_err(|_| InspectorError::new(message))
}

fn read_pin_root(path: &Path) -> PinRootSnapshot {
    if !path.exists() {
        return PinRootSnapshot::absent();
    }
    match fs::read_dir(path) {
        Ok(entries) => PinRootSnapshot::foreign(entries.filter_map(Result::ok).count()),
        Err(_) => PinRootSnapshot::foreign(1),
    }
}

#[derive(Debug, Default)]
pub struct SystemCommandSource;

impl CommandSource for SystemCommandSource {
    fn query_ovs_bridge(
        &mut self,
        interface: &InterfaceName,
    ) -> Result<Option<InterfaceName>, InspectorError> {
        let interface = interface.clone();
        run_async(move || async move {
            let mut command = tokio::process::Command::new("ovs-vsctl");
            command
                .args(ovs_vsctl_args(&interface))
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(2), command.output())
                .await
                .map_err(|_| InspectorError::new("Open vSwitch query timed out"))?
                .map_err(|_| InspectorError::new("Open vSwitch query is unavailable"))?;
            if !output.status.success() {
                return Err(InspectorError::new("Open vSwitch query failed"));
            }
            parse_ovs_bridge_name(&output.stdout)
                .map_err(|_| InspectorError::new("Open vSwitch query returned invalid output"))
        })
    }
}

#[derive(Debug, Default)]
pub struct SystemBpfQuery;

impl BpfQuery for SystemBpfQuery {
    fn query_bpf(&mut self, ifindexes: &[u32]) -> Result<BpfQuerySnapshot, InspectorError> {
        let ifindexes = ifindexes.to_vec();
        run_async(move || async move {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|_| InspectorError::new("failed to open Linux BPF query"))?;
            tokio::spawn(connection);

            let (xdp_native, xdp_generic, xdp_known) = query_xdp(&handle, &ifindexes).await;
            let (tc_ingress, ingress_known) =
                query_tc(&handle, &ifindexes, Direction::Ingress).await;
            let (tc_egress, egress_known) = query_tc(&handle, &ifindexes, Direction::Egress).await;
            let tc_clsact = query_qdisc_capability(&handle, &ifindexes).await;
            let tc_state_known = ingress_known && egress_known;

            Ok(BpfQuerySnapshot {
                bpf_syscall: bpf_syscall_available(),
                relevant_objects_enumerable: xdp_known && tc_state_known,
                xdp_native,
                xdp_generic,
                tc_state_known,
                tc_clsact,
                tc_ingress,
                tc_egress,
            })
        })
    }
}

async fn query_xdp(
    handle: &rtnetlink::Handle,
    ifindexes: &[u32],
) -> (AttachmentState, AttachmentState, bool) {
    let mut native = AttachmentState::Empty;
    let mut generic = AttachmentState::Empty;
    for ifindex in ifindexes {
        let mut messages = handle.link().get().match_index(*ifindex).execute();
        let message = match messages.try_next().await {
            Ok(Some(message)) => message,
            _ => return (AttachmentState::Unknown, AttachmentState::Unknown, false),
        };
        let (observed_native, observed_generic) = xdp_states(&message);
        native = merge_attachment_state(native, observed_native);
        generic = merge_attachment_state(generic, observed_generic);
    }
    (native, generic, true)
}

fn xdp_states(message: &LinkMessage) -> (AttachmentState, AttachmentState) {
    let mut attached = None;
    let mut program_id = None;
    let mut driver_id = None;
    let mut generic_id = None;
    let mut hardware_id = None;
    for attribute in &message.attributes {
        if let LinkAttribute::Xdp(attributes) = attribute {
            for xdp in attributes {
                match xdp {
                    LinkXdp::Attached(value) => attached = Some(*value),
                    LinkXdp::ProgId(value) if *value != 0 => program_id = Some(*value),
                    LinkXdp::DrvProgId(value) if *value != 0 => driver_id = Some(*value),
                    LinkXdp::SkbProgId(value) if *value != 0 => generic_id = Some(*value),
                    LinkXdp::HwProgId(value) if *value != 0 => hardware_id = Some(*value),
                    _ => {}
                }
            }
        }
    }
    let mut native = driver_id.map_or(AttachmentState::Empty, occupied);
    let mut generic = generic_id.map_or(AttachmentState::Empty, occupied);
    if hardware_id.is_some() {
        native = AttachmentState::Unknown;
        generic = AttachmentState::Unknown;
    }
    if let Some(attached) = attached {
        use rtnetlink::packet_route::link::XdpAttached;
        match attached {
            XdpAttached::None => {}
            XdpAttached::Driver if driver_id.is_none() => {
                native = program_id.map_or(AttachmentState::Unknown, occupied);
            }
            XdpAttached::SocketBuffer if generic_id.is_none() => {
                generic = program_id.map_or(AttachmentState::Unknown, occupied);
            }
            XdpAttached::Multiple => {
                if driver_id.is_none() {
                    native = AttachmentState::Unknown;
                }
                if generic_id.is_none() {
                    generic = AttachmentState::Unknown;
                }
            }
            XdpAttached::Hardware | XdpAttached::Other(_) => {
                native = AttachmentState::Unknown;
                generic = AttachmentState::Unknown;
            }
            _ => {}
        }
    } else if program_id.is_some() && driver_id.is_none() && generic_id.is_none() {
        native = AttachmentState::Unknown;
        generic = AttachmentState::Unknown;
    }
    (native, generic)
}

const fn occupied(program_id: u32) -> AttachmentState {
    AttachmentState::Occupied { program_id }
}

fn merge_attachment_state(left: AttachmentState, right: AttachmentState) -> AttachmentState {
    match (left, right) {
        (AttachmentState::Unknown, _) | (_, AttachmentState::Unknown) => AttachmentState::Unknown,
        (AttachmentState::Occupied { program_id }, _)
        | (_, AttachmentState::Occupied { program_id }) => AttachmentState::Occupied { program_id },
        (AttachmentState::Owned { program_id }, _) | (_, AttachmentState::Owned { program_id }) => {
            AttachmentState::Owned { program_id }
        }
        _ => AttachmentState::Empty,
    }
}

async fn query_tc(
    handle: &rtnetlink::Handle,
    ifindexes: &[u32],
    direction: Direction,
) -> (Vec<ObservedTcAttachment>, bool) {
    let mut observed = Vec::new();
    for ifindex in ifindexes {
        let request = handle.traffic_filter(*ifindex as i32).get();
        let mut messages = match direction {
            Direction::Ingress => request.ingress().execute(),
            Direction::Egress => request.egress().execute(),
        };
        loop {
            match messages.try_next().await {
                Ok(Some(message)) => match tc_attachment(&message, direction) {
                    ParsedTcAttachment::Known(attachment) => {
                        observed.push(ObservedTcAttachment {
                            attachment,
                            owned: false,
                        });
                    }
                    ParsedTcAttachment::NotBpf => {}
                    ParsedTcAttachment::Unknown => return (observed, false),
                },
                Ok(None) => break,
                Err(_) => return (observed, false),
            }
        }
    }
    (observed, true)
}

enum ParsedTcAttachment {
    NotBpf,
    Known(TcAttachment),
    Unknown,
}

fn tc_attachment(message: &TcMessage, direction: Direction) -> ParsedTcAttachment {
    let is_bpf = message
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, TcAttribute::Kind(kind) if kind == "bpf"));
    if !is_bpf {
        return ParsedTcAttachment::NotBpf;
    }
    let program_id = message.attributes.iter().find_map(|attribute| {
        let TcAttribute::Options(options) = attribute else {
            return None;
        };
        options.iter().find_map(|option| match option {
            TcOption::Bpf(TcFilterBpfOption::ProgId(program_id)) => Some(*program_id),
            _ => None,
        })
    });
    let Some(program_id) = program_id else {
        return ParsedTcAttachment::Unknown;
    };

    ParsedTcAttachment::Known(TcAttachment {
        direction,
        priority: (message.header.info >> 16) as u16,
        handle: message.header.handle.into(),
        program_id,
    })
}

async fn query_qdisc_capability(handle: &rtnetlink::Handle, ifindexes: &[u32]) -> bool {
    for ifindex in ifindexes {
        let mut messages = handle.qdisc().get().index(*ifindex as i32).execute();
        loop {
            match messages.try_next().await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return false,
            }
        }
    }
    true
}

fn bpf_syscall_available() -> bool {
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_bpf,
            u32::MAX,
            std::ptr::null::<nix::libc::c_void>(),
            0,
        )
    };
    result != -1 || nix::errno::Errno::last() == nix::errno::Errno::EINVAL
}

fn run_async<T, F, Fut>(operation: F) -> Result<T, InspectorError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, InspectorError>> + Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| InspectorError::new("failed to start inspection runtime"))?
            .block_on(operation())
    })
    .join()
    .map_err(|_| InspectorError::new("inspection worker stopped unexpectedly"))?
}

pub type SystemLinuxInspector =
    LinuxInspector<SystemLinkSource, SystemFileSource, SystemBpfQuery, SystemCommandSource>;

impl LinuxInspector<SystemLinkSource, SystemFileSource, SystemBpfQuery, SystemCommandSource> {
    pub fn system() -> Self {
        Self::new(
            SystemLinkSource,
            SystemFileSource,
            SystemBpfQuery,
            SystemCommandSource,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::tc::TcHandle;

    #[test]
    fn host_inventory_accepts_a_backed_tc_filter_summary() {
        let mut summary = tc_message(147, 0);
        let mut concrete = tc_message(147, 0x4c32_0002);
        concrete
            .attributes
            .push(TcAttribute::Options(vec![TcOption::Bpf(
                TcFilterBpfOption::ProgId(4813548),
            )]));

        let (observed, known) =
            observed_tc_from_messages(147, Direction::Egress, [&summary, &concrete]);

        assert!(known);
        assert_eq!(
            observed,
            vec![ObservedTcAttachment {
                attachment: TcAttachment {
                    direction: Direction::Egress,
                    priority: 49_600,
                    handle: 0x4c32_0002,
                    program_id: 4813548,
                },
                owned: false,
            }],
        );

        summary
            .attributes
            .push(TcAttribute::Options(Vec::new()));
        assert!(!observed_tc_from_messages(147, Direction::Egress, [&summary]).1);
    }

    fn tc_message(ifindex: i32, handle: u32) -> TcMessage {
        let mut message = TcMessage::with_index(ifindex);
        message.header.handle = handle.into();
        message.header.parent = TcHandle {
            major: u16::MAX,
            minor: TcHandle::MIN_EGRESS,
        };
        message.header.info = u32::from(TcHandle {
            major: 49_600,
            minor: 0x0003_u16.to_be(),
        });
        message
            .attributes
            .push(TcAttribute::Kind("bpf".to_owned()));
        message
    }
}
