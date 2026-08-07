use std::{
    future::Future,
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use futures_util::TryStreamExt;
use l2_loop_core::{PF_XDP_OCCUPIED, PF_XDP_STATE_UNKNOWN};
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage, LinkXdp, XdpAttached};

use crate::ownership::{OwnedXdp, XdpAttachMode, XdpKernelIdentity};

pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

const XDP_ATTACH_FAILED: &str = "XDP_ATTACH_FAILED";
const XDP_VERIFY_FAILED: &str = "XDP_VERIFY_FAILED";
const XDP_DETACH_FAILED: &str = "XDP_DETACH_FAILED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedXdp {
    pub program_fd: RawFd,
    pub program_id: u32,
    pub program_tag: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpSlot {
    Empty,
    Attached(XdpKernelIdentity),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpInventory {
    pub native: XdpSlot,
    pub generic: XdpSlot,
}

impl XdpInventory {
    pub const fn empty() -> Self {
        Self {
            native: XdpSlot::Empty,
            generic: XdpSlot::Empty,
        }
    }

    pub const fn only(mode: XdpAttachMode, slot: XdpSlot) -> Self {
        match mode {
            XdpAttachMode::Native => Self {
                native: slot,
                generic: XdpSlot::Empty,
            },
            XdpAttachMode::Generic => Self {
                native: XdpSlot::Empty,
                generic: slot,
            },
        }
    }

    const fn slot(self, mode: XdpAttachMode) -> XdpSlot {
        match mode {
            XdpAttachMode::Native => self.native,
            XdpAttachMode::Generic => self.generic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpState {
    Empty,
    Owned,
    Foreign,
    Unknown,
}

pub fn classify_inventory(inventory: &XdpInventory, owned: Option<&OwnedXdp>) -> XdpState {
    let slots = [inventory.native, inventory.generic];
    if slots.contains(&XdpSlot::Unknown) {
        return XdpState::Unknown;
    }

    let mut attached = slots.iter().filter_map(|slot| match slot {
        XdpSlot::Attached(identity) => Some(identity),
        XdpSlot::Empty | XdpSlot::Unknown => None,
    });
    let Some(first) = attached.next() else {
        return XdpState::Empty;
    };
    if attached.next().is_some() {
        return XdpState::Foreign;
    }
    if owned.is_some_and(|record| record.matches(first)) {
        XdpState::Owned
    } else {
        XdpState::Foreign
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdpIoError {
    Exists,
    Failed(String),
}

pub trait XdpIo {
    fn query(&mut self, ifindex: u32) -> Result<XdpInventory, XdpIoError>;
    fn attach_no_replace(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        program_fd: RawFd,
    ) -> Result<(), XdpIoError>;
    fn detach_if_matches(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        expected_program_id: u32,
    ) -> Result<(), XdpIoError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpRollback {
    Completed,
    Failed,
    RetainedIdentityMismatch,
    RetainedUnknownState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpDetachOutcome {
    Detached,
    AlreadyAbsent,
    RetainedIdentityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpError {
    code: &'static str,
    evidence: String,
    rollback: Option<XdpRollback>,
}

impl XdpError {
    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn rollback(&self) -> Option<XdpRollback> {
        self.rollback
    }

    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    fn new(code: &'static str, evidence: impl Into<String>) -> Self {
        Self {
            code,
            evidence: evidence.into(),
            rollback: None,
        }
    }

    fn verification(evidence: impl Into<String>, rollback: XdpRollback) -> Self {
        Self {
            code: XDP_VERIFY_FAILED,
            evidence: evidence.into(),
            rollback: Some(rollback),
        }
    }
}

pub struct SafeXdp<I> {
    io: I,
}

impl<I: XdpIo> SafeXdp<I> {
    pub const fn new(io: I) -> Self {
        Self { io }
    }

    pub fn attach(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        loaded: LoadedXdp,
    ) -> Result<OwnedXdp, XdpError> {
        let before = self.query_or_unknown(ifindex)?;
        match classify_inventory(&before, None) {
            XdpState::Empty => {}
            XdpState::Foreign | XdpState::Owned => {
                return Err(XdpError::new(
                    PF_XDP_OCCUPIED,
                    "an XDP hook is already occupied",
                ));
            }
            XdpState::Unknown => return Err(unknown_state()),
        }

        match self.io.attach_no_replace(ifindex, mode, loaded.program_fd) {
            Ok(()) => {}
            Err(XdpIoError::Exists) => {
                return Err(XdpError::new(
                    PF_XDP_OCCUPIED,
                    "atomic XDP no-replace attach found an occupied hook",
                ));
            }
            Err(XdpIoError::Failed(_)) => {
                return Err(XdpError::new(
                    XDP_ATTACH_FAILED,
                    "atomic XDP no-replace attach failed",
                ));
            }
        }

        let after = match self.io.query(ifindex) {
            Ok(inventory) => inventory,
            Err(_) => {
                return Err(XdpError::verification(
                    "XDP identity could not be verified after attach",
                    XdpRollback::RetainedUnknownState,
                ));
            }
        };
        let owned = OwnedXdp {
            ifindex,
            mode,
            program_id: loaded.program_id,
            program_tag: loaded.program_tag,
            link_id: None,
        };
        if classify_inventory(&after, Some(&owned)) == XdpState::Owned {
            return Ok(owned);
        }

        let rollback = match after.slot(mode) {
            XdpSlot::Attached(current) if current.program_id == loaded.program_id => {
                match self.io.detach_if_matches(ifindex, mode, loaded.program_id) {
                    Ok(()) => XdpRollback::Completed,
                    Err(_) => XdpRollback::Failed,
                }
            }
            XdpSlot::Unknown => XdpRollback::RetainedUnknownState,
            XdpSlot::Empty | XdpSlot::Attached(_) => XdpRollback::RetainedIdentityMismatch,
        };
        Err(XdpError::verification(
            "post-attach XDP identity did not match the loaded program",
            rollback,
        ))
    }

    pub fn detach(&mut self, owned: &OwnedXdp) -> Result<XdpDetachOutcome, XdpError> {
        let current = self.query_or_unknown(owned.ifindex)?;
        match classify_inventory(&current, Some(owned)) {
            XdpState::Empty => Ok(XdpDetachOutcome::AlreadyAbsent),
            XdpState::Owned => self
                .io
                .detach_if_matches(owned.ifindex, owned.mode, owned.program_id)
                .map(|()| XdpDetachOutcome::Detached)
                .map_err(|_| {
                    XdpError::new(
                        XDP_DETACH_FAILED,
                        "atomic owned XDP detach failed without broad cleanup",
                    )
                }),
            XdpState::Foreign => Ok(XdpDetachOutcome::RetainedIdentityMismatch),
            XdpState::Unknown => Err(unknown_state()),
        }
    }

    fn query_or_unknown(&mut self, ifindex: u32) -> Result<XdpInventory, XdpError> {
        self.io.query(ifindex).map_err(|_| unknown_state())
    }
}

fn unknown_state() -> XdpError {
    XdpError::new(
        PF_XDP_STATE_UNKNOWN,
        "XDP state could not be determined safely",
    )
}

pub fn encode_attach_request(ifindex: u32, mode: XdpAttachMode, program_fd: RawFd) -> LinkMessage {
    encode_request(
        ifindex,
        program_fd,
        mode_flags(mode) | XDP_FLAGS_UPDATE_IF_NOEXIST,
        None,
    )
}

pub fn encode_detach_request(ifindex: u32, mode: XdpAttachMode, expected_fd: RawFd) -> LinkMessage {
    encode_request(ifindex, -1, mode_flags(mode), Some(expected_fd))
}

fn encode_request(
    ifindex: u32,
    program_fd: RawFd,
    flags: u32,
    expected_fd: Option<RawFd>,
) -> LinkMessage {
    let mut xdp = vec![LinkXdp::Fd(program_fd), LinkXdp::Flags(flags)];
    if let Some(fd) = expected_fd {
        xdp.push(LinkXdp::ExpectedFd(fd as u32));
    }
    let mut message = LinkMessage::default();
    message.header.index = ifindex;
    message.attributes.push(LinkAttribute::Xdp(xdp));
    message
}

const fn mode_flags(mode: XdpAttachMode) -> u32 {
    match mode {
        XdpAttachMode::Native => XDP_FLAGS_DRV_MODE,
        XdpAttachMode::Generic => XDP_FLAGS_SKB_MODE,
    }
}

#[derive(Debug, Default)]
pub struct RtnetlinkXdpIo;

impl XdpIo for RtnetlinkXdpIo {
    fn query(&mut self, ifindex: u32) -> Result<XdpInventory, XdpIoError> {
        run_async(move || async move {
            let (connection, handle, _) = rtnetlink::new_connection()
                .map_err(|_| failed("failed to open XDP state query"))?;
            tokio::spawn(connection);
            let mut messages = handle.link().get().match_index(ifindex).execute();
            let message = messages
                .try_next()
                .await
                .map_err(|_| failed("failed to query XDP state"))?
                .ok_or_else(|| failed("XDP target interface is missing"))?;
            if message.header.index != ifindex {
                return Err(failed("XDP query returned a different interface"));
            }
            inventory_from_message(&message)
        })
    }

    fn attach_no_replace(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        program_fd: RawFd,
    ) -> Result<(), XdpIoError> {
        let message = encode_attach_request(ifindex, mode, program_fd);
        run_set(message)
    }

    fn detach_if_matches(
        &mut self,
        ifindex: u32,
        mode: XdpAttachMode,
        expected_program_id: u32,
    ) -> Result<(), XdpIoError> {
        let expected_fd = program_fd_by_id(expected_program_id)
            .map_err(|_| failed("owned XDP program identity is no longer available"))?;
        let message = encode_detach_request(ifindex, mode, expected_fd.as_raw_fd());
        run_set(message)
    }
}

fn run_set(message: LinkMessage) -> Result<(), XdpIoError> {
    run_async(move || async move {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|_| failed("failed to open XDP netlink operation"))?;
        tokio::spawn(connection);
        handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(netlink_error)
    })
}

fn inventory_from_message(message: &LinkMessage) -> Result<XdpInventory, XdpIoError> {
    let mut attached = None;
    let mut program_id = None;
    let mut native_id = None;
    let mut generic_id = None;
    let mut hardware_id = None;
    for attribute in &message.attributes {
        if let LinkAttribute::Xdp(values) = attribute {
            for value in values {
                match value {
                    LinkXdp::Attached(value) => attached = Some(*value),
                    LinkXdp::ProgId(value) if *value != 0 => program_id = Some(*value),
                    LinkXdp::DrvProgId(value) if *value != 0 => native_id = Some(*value),
                    LinkXdp::SkbProgId(value) if *value != 0 => generic_id = Some(*value),
                    LinkXdp::HwProgId(value) if *value != 0 => hardware_id = Some(*value),
                    _ => {}
                }
            }
        }
    }

    if hardware_id.is_some() {
        return Ok(XdpInventory {
            native: XdpSlot::Unknown,
            generic: XdpSlot::Unknown,
        });
    }
    let mut native = slot_from_program(message.header.index, XdpAttachMode::Native, native_id);
    let mut generic = slot_from_program(message.header.index, XdpAttachMode::Generic, generic_id);
    match attached {
        Some(XdpAttached::Driver) if native_id.is_none() => {
            native = slot_from_program(message.header.index, XdpAttachMode::Native, program_id);
        }
        Some(XdpAttached::SocketBuffer) if generic_id.is_none() => {
            generic = slot_from_program(message.header.index, XdpAttachMode::Generic, program_id);
        }
        Some(XdpAttached::Multiple) => {
            if native_id.is_none() {
                native = XdpSlot::Unknown;
            }
            if generic_id.is_none() {
                generic = XdpSlot::Unknown;
            }
        }
        Some(XdpAttached::Hardware | XdpAttached::Other(_)) => {
            native = XdpSlot::Unknown;
            generic = XdpSlot::Unknown;
        }
        None if program_id.is_some() && native_id.is_none() && generic_id.is_none() => {
            native = XdpSlot::Unknown;
            generic = XdpSlot::Unknown;
        }
        _ => {}
    }
    Ok(XdpInventory { native, generic })
}

fn slot_from_program(ifindex: u32, mode: XdpAttachMode, id: Option<u32>) -> XdpSlot {
    let Some(program_id) = id else {
        return XdpSlot::Empty;
    };
    match program_tag(program_id) {
        Ok(program_tag) => XdpSlot::Attached(XdpKernelIdentity {
            ifindex,
            mode,
            program_id,
            program_tag,
            link_id: None,
        }),
        Err(_) => XdpSlot::Unknown,
    }
}

fn netlink_error(error: rtnetlink::Error) -> XdpIoError {
    if matches!(
        &error,
        rtnetlink::Error::NetlinkError(message)
            if message.to_io().raw_os_error() == Some(nix::libc::EEXIST)
    ) {
        XdpIoError::Exists
    } else {
        failed("XDP netlink operation failed")
    }
}

fn failed(message: &str) -> XdpIoError {
    XdpIoError::Failed(message.to_owned())
}

fn run_async<T, F, Fut>(operation: F) -> Result<T, XdpIoError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, XdpIoError>> + Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| failed("failed to start XDP runtime"))?
            .block_on(operation())
    })
    .join()
    .map_err(|_| failed("XDP worker stopped unexpectedly"))?
}

const BPF_PROG_GET_FD_BY_ID: nix::libc::c_long = 13;
const BPF_OBJ_GET_INFO_BY_FD: nix::libc::c_long = 15;

#[repr(C)]
#[derive(Default)]
struct BpfGetFdByIdAttr {
    program_id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
struct BpfInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfProgramIdentity {
    program_type: u32,
    id: u32,
    tag: [u8; 8],
}

fn program_fd_by_id(program_id: u32) -> io::Result<OwnedFd> {
    let attr = BpfGetFdByIdAttr {
        program_id,
        ..Default::default()
    };
    let fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_bpf,
            BPF_PROG_GET_FD_BY_ID,
            &attr,
            size_of::<BpfGetFdByIdAttr>(),
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

fn program_tag(program_id: u32) -> io::Result<[u8; 8]> {
    let fd = program_fd_by_id(program_id)?;
    let mut info = BpfProgramIdentity::default();
    let attr = BpfInfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of::<BpfProgramIdentity>() as u32,
        info: (&mut info as *mut BpfProgramIdentity) as u64,
    };
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &attr,
            size_of::<BpfInfoAttr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else if info.id != program_id {
        Err(io::Error::other("BPF program identity changed"))
    } else {
        Ok(info.tag)
    }
}
