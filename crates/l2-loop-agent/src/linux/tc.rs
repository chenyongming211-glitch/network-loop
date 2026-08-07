use std::{future::Future, os::fd::RawFd};

use futures_util::{StreamExt, TryStreamExt};
use l2_loop_core::{PF_TC_HANDLE_COLLISION, PF_TC_STATE_UNKNOWN};
use rtnetlink::{
    packet_core::{
        NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
    },
    packet_route::{
        RouteNetlinkMessage,
        tc::{TcAttribute, TcBpfFlags, TcFilterBpfOption, TcHandle, TcMessage, TcOption},
    },
};

use crate::{
    ownership::{OwnedTc, TcHook, TcKernelIdentity},
    ports::{PortError, SafeTcPort},
};

pub const TC_INGRESS_HANDLE: u32 = 0x4c32_0001;
pub const TC_EGRESS_HANDLE: u32 = 0x4c32_0002;
pub const TC_PRIORITY_FIRST: u16 = 49_600;
pub const TC_PRIORITY_LAST: u16 = 49_699;

const ETH_P_ALL: u16 = 0x0003;
const TC_ATTACH_FAILED: &str = "TC_ATTACH_FAILED";
const TC_VERIFY_FAILED: &str = "TC_VERIFY_FAILED";
const TC_DETACH_FAILED: &str = "TC_DETACH_FAILED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedTc {
    pub program_fd: RawFd,
    pub program_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcClsactState {
    Absent,
    Present,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcFilterSlot {
    Bpf(TcKernelIdentity),
    Other {
        hook: TcHook,
        priority: u16,
        handle: u32,
    },
    Unknown(TcHook),
}

impl TcFilterSlot {
    const fn hook(self) -> TcHook {
        match self {
            Self::Bpf(identity) => identity.hook,
            Self::Other { hook, .. } | Self::Unknown(hook) => hook,
        }
    }

    const fn priority(self) -> Option<u16> {
        match self {
            Self::Bpf(identity) => Some(identity.priority),
            Self::Other { priority, .. } => Some(priority),
            Self::Unknown(_) => None,
        }
    }

    const fn handle(self) -> Option<u32> {
        match self {
            Self::Bpf(identity) => Some(identity.handle),
            Self::Other { handle, .. } => Some(handle),
            Self::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcInventory {
    pub clsact: TcClsactState,
    pub filters: Vec<TcFilterSlot>,
}

impl TcInventory {
    pub const fn empty(clsact: TcClsactState) -> Self {
        Self {
            clsact,
            filters: Vec::new(),
        }
    }

    pub fn only(clsact: TcClsactState, filter: TcFilterSlot) -> Self {
        Self {
            clsact,
            filters: vec![filter],
        }
    }

    pub const fn new(clsact: TcClsactState, filters: Vec<TcFilterSlot>) -> Self {
        Self { clsact, filters }
    }

    fn has_exact(&self, expected: TcKernelIdentity) -> bool {
        self.filters.contains(&TcFilterSlot::Bpf(expected))
    }

    fn has_unknown(&self) -> bool {
        self.clsact == TcClsactState::Unknown
            || self
                .filters
                .iter()
                .any(|slot| matches!(slot, TcFilterSlot::Unknown(_)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcState {
    Empty { priority: u16, clsact_present: bool },
    Owned,
    Foreign,
    Unknown,
}

pub fn classify_inventory(
    inventory: &TcInventory,
    hook: TcHook,
    owned: Option<&OwnedTc>,
) -> TcState {
    if inventory.has_unknown()
        || (inventory.clsact == TcClsactState::Absent && !inventory.filters.is_empty())
    {
        return TcState::Unknown;
    }

    let reserved_handle = handle_for(hook);
    let reserved: Vec<TcFilterSlot> = inventory
        .filters
        .iter()
        .copied()
        .filter(|slot| slot.hook() == hook && slot.handle() == Some(reserved_handle))
        .collect();
    if let [TcFilterSlot::Bpf(identity)] = reserved.as_slice() {
        return if owned.is_some_and(|record| record.matches(identity)) {
            TcState::Owned
        } else {
            TcState::Foreign
        };
    }
    if !reserved.is_empty() {
        return TcState::Foreign;
    }

    let priority = (TC_PRIORITY_FIRST..=TC_PRIORITY_LAST).find(|candidate| {
        !inventory.filters.iter().copied().any(|slot| {
            slot.hook() == hook && slot.priority().is_some_and(|value| value == *candidate)
        })
    });
    match priority {
        Some(priority) => TcState::Empty {
            priority,
            clsact_present: inventory.clsact == TcClsactState::Present,
        },
        None => TcState::Foreign,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcIoError {
    Exists,
    IdentityMismatch,
    Failed(String),
}

pub trait TcIo {
    fn query(&mut self, ifindex: u32) -> Result<TcInventory, TcIoError>;
    fn ensure_clsact_exclusive(&mut self, ifindex: u32) -> Result<(), TcIoError>;
    fn attach_exclusive(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        priority: u16,
        handle: u32,
        program_fd: RawFd,
    ) -> Result<(), TcIoError>;
    fn detach_exact(&mut self, identity: TcKernelIdentity) -> Result<(), TcIoError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcRollback {
    Completed,
    Failed,
    RetainedIdentityMismatch,
    RetainedUnknownState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcDetachOutcome {
    Detached,
    AlreadyAbsent,
    RetainedIdentityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcError {
    code: &'static str,
    evidence: String,
    rollback: Option<TcRollback>,
}

impl TcError {
    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn rollback(&self) -> Option<TcRollback> {
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

    fn verification(evidence: impl Into<String>, rollback: TcRollback) -> Self {
        Self {
            code: TC_VERIFY_FAILED,
            evidence: evidence.into(),
            rollback: Some(rollback),
        }
    }
}

pub struct SafeTc<I> {
    io: I,
}

impl<I: TcIo> SafeTc<I> {
    pub const fn new(io: I) -> Self {
        Self { io }
    }

    pub fn attach(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        loaded: LoadedTc,
    ) -> Result<OwnedTc, TcError> {
        let before = self.query_or_unknown(ifindex)?;
        let (mut priority, clsact_present) = empty_plan(&before, hook)?;
        let mut created_clsact = false;

        if !clsact_present {
            match self.io.ensure_clsact_exclusive(ifindex) {
                Ok(()) => created_clsact = true,
                Err(TcIoError::Exists) => {
                    let raced = self.query_or_unknown(ifindex)?;
                    let (raced_priority, raced_clsact_present) = empty_plan(&raced, hook)?;
                    if !raced_clsact_present {
                        return Err(occupied("clsact is occupied by a different qdisc"));
                    }
                    priority = raced_priority;
                }
                Err(TcIoError::IdentityMismatch | TcIoError::Failed(_)) => {
                    return Err(TcError::new(
                        TC_ATTACH_FAILED,
                        "exclusive clsact creation failed",
                    ));
                }
            }
        }

        let filter_handle = handle_for(hook);
        match self
            .io
            .attach_exclusive(ifindex, hook, priority, filter_handle, loaded.program_fd)
        {
            Ok(()) => {}
            Err(TcIoError::Exists) => {
                return Err(occupied(
                    "exclusive TC filter creation found an occupied slot",
                ));
            }
            Err(TcIoError::IdentityMismatch | TcIoError::Failed(_)) => {
                return Err(TcError::new(
                    TC_ATTACH_FAILED,
                    "exclusive TC filter creation failed",
                ));
            }
        }

        let owned = OwnedTc {
            ifindex,
            hook,
            priority,
            handle: filter_handle,
            program_id: loaded.program_id,
            created_clsact,
        };
        let after = match self.io.query(ifindex) {
            Ok(inventory) => inventory,
            Err(_) => {
                return Err(TcError::verification(
                    "TC identity could not be verified after attach",
                    TcRollback::RetainedUnknownState,
                ));
            }
        };
        if classify_inventory(&after, hook, Some(&owned)) == TcState::Owned {
            return Ok(owned);
        }

        let expected = TcKernelIdentity::from(owned);
        let rollback = if after.has_exact(expected) {
            match self.io.detach_exact(expected) {
                Ok(()) => TcRollback::Completed,
                Err(_) => TcRollback::Failed,
            }
        } else if after.has_unknown() {
            TcRollback::RetainedUnknownState
        } else {
            TcRollback::RetainedIdentityMismatch
        };
        Err(TcError::verification(
            "post-attach TC identity did not match the loaded program",
            rollback,
        ))
    }

    pub fn detach(&mut self, owned: &OwnedTc) -> Result<TcDetachOutcome, TcError> {
        let current = self.query_or_unknown(owned.ifindex)?;
        match classify_inventory(&current, owned.hook, Some(owned)) {
            TcState::Empty { .. } => Ok(TcDetachOutcome::AlreadyAbsent),
            TcState::Owned => self
                .io
                .detach_exact((*owned).into())
                .map(|()| TcDetachOutcome::Detached)
                .map_err(|_| {
                    TcError::new(
                        TC_DETACH_FAILED,
                        "exact owned TC detach failed without broad cleanup",
                    )
                }),
            TcState::Foreign => Ok(TcDetachOutcome::RetainedIdentityMismatch),
            TcState::Unknown => Err(unknown_state()),
        }
    }

    pub fn verify(&mut self, owned: &OwnedTc) -> Result<(), TcError> {
        let current = self.query_or_unknown(owned.ifindex)?;
        match classify_inventory(&current, owned.hook, Some(owned)) {
            TcState::Owned => Ok(()),
            TcState::Empty { .. } | TcState::Foreign => Err(TcError::new(
                TC_VERIFY_FAILED,
                "current TC identity does not match the owned filter",
            )),
            TcState::Unknown => Err(unknown_state()),
        }
    }

    fn query_or_unknown(&mut self, ifindex: u32) -> Result<TcInventory, TcError> {
        self.io.query(ifindex).map_err(|_| unknown_state())
    }
}

impl<I: TcIo> SafeTcPort for SafeTc<I> {
    fn attach_explicit(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        loaded: LoadedTc,
    ) -> Result<OwnedTc, PortError> {
        self.attach(ifindex, hook, loaded).map_err(tc_port_error)
    }

    fn verify_exact(&mut self, owned: &OwnedTc) -> Result<(), PortError> {
        self.verify(owned).map_err(tc_port_error)
    }

    fn detach_exact(&mut self, owned: &OwnedTc) -> Result<(), PortError> {
        match self.detach(owned).map_err(tc_port_error)? {
            TcDetachOutcome::Detached | TcDetachOutcome::AlreadyAbsent => Ok(()),
            TcDetachOutcome::RetainedIdentityMismatch => Err(PortError::Adapter(
                "owned TC identity changed; filter was retained".to_owned(),
            )),
        }
    }
}

fn tc_port_error(error: TcError) -> PortError {
    PortError::Adapter(format!("{}: {}", error.code(), error.evidence()))
}

fn empty_plan(inventory: &TcInventory, hook: TcHook) -> Result<(u16, bool), TcError> {
    match classify_inventory(inventory, hook, None) {
        TcState::Empty {
            priority,
            clsact_present,
        } => Ok((priority, clsact_present)),
        TcState::Owned | TcState::Foreign => Err(occupied("TC reserved identity is occupied")),
        TcState::Unknown => Err(unknown_state()),
    }
}

fn occupied(evidence: impl Into<String>) -> TcError {
    TcError::new(PF_TC_HANDLE_COLLISION, evidence)
}

fn unknown_state() -> TcError {
    TcError::new(
        PF_TC_STATE_UNKNOWN,
        "TC state could not be determined safely",
    )
}

pub const fn attach_request_flags() -> u16 {
    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
}

pub fn encode_clsact_request(ifindex: u32) -> TcMessage {
    let mut message = TcMessage::with_index(ifindex as i32);
    message.header.handle = TcHandle {
        major: u16::MAX,
        minor: 0,
    };
    message.header.parent = TcHandle::CLSACT;
    message
        .attributes
        .push(TcAttribute::Kind("clsact".to_owned()));
    message
}

pub fn encode_attach_request(
    ifindex: u32,
    hook: TcHook,
    priority: u16,
    handle: u32,
    program_fd: RawFd,
) -> TcMessage {
    let mut message = encode_filter_identity(ifindex, hook, priority, handle);
    message.attributes.push(TcAttribute::Options(vec![
        TcOption::Bpf(TcFilterBpfOption::ProgFd(program_fd as u32)),
        TcOption::Bpf(TcFilterBpfOption::ProgName("l2_loop_tc".to_owned())),
        TcOption::Bpf(TcFilterBpfOption::Flags(TcBpfFlags::DirectAction)),
    ]));
    message
}

pub fn encode_detach_request(identity: TcKernelIdentity) -> TcMessage {
    let mut message = encode_filter_identity(
        identity.ifindex,
        identity.hook,
        identity.priority,
        identity.handle,
    );
    message.attributes.push(TcAttribute::Options(Vec::new()));
    message
}

fn encode_filter_identity(ifindex: u32, hook: TcHook, priority: u16, handle: u32) -> TcMessage {
    let mut message = TcMessage::with_index(ifindex as i32);
    message.header.handle = handle.into();
    message.header.parent = parent_for(hook);
    message.header.info = u32::from(TcHandle {
        major: priority,
        minor: ETH_P_ALL,
    });
    message.attributes.push(TcAttribute::Kind("bpf".to_owned()));
    message
}

const fn handle_for(hook: TcHook) -> u32 {
    match hook {
        TcHook::Ingress => TC_INGRESS_HANDLE,
        TcHook::Egress => TC_EGRESS_HANDLE,
    }
}

const fn parent_for(hook: TcHook) -> TcHandle {
    match hook {
        TcHook::Ingress => TcHandle {
            major: u16::MAX,
            minor: TcHandle::MIN_INGRESS,
        },
        TcHook::Egress => TcHandle {
            major: u16::MAX,
            minor: TcHandle::MIN_EGRESS,
        },
    }
}

#[derive(Debug, Default)]
pub struct RtnetlinkTcIo;

impl TcIo for RtnetlinkTcIo {
    fn query(&mut self, ifindex: u32) -> Result<TcInventory, TcIoError> {
        run_async(move || query_inventory(ifindex))
    }

    fn ensure_clsact_exclusive(&mut self, ifindex: u32) -> Result<(), TcIoError> {
        let message = encode_clsact_request(ifindex);
        run_async(move || send_request(TcRequest::NewQdisc(message), attach_request_flags()))
    }

    fn attach_exclusive(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        priority: u16,
        handle: u32,
        program_fd: RawFd,
    ) -> Result<(), TcIoError> {
        let message = encode_attach_request(ifindex, hook, priority, handle, program_fd);
        run_async(move || send_request(TcRequest::NewFilter(message), attach_request_flags()))
    }

    fn detach_exact(&mut self, identity: TcKernelIdentity) -> Result<(), TcIoError> {
        run_async(move || async move {
            let current = query_inventory(identity.ifindex).await?;
            let owned = OwnedTc {
                ifindex: identity.ifindex,
                hook: identity.hook,
                priority: identity.priority,
                handle: identity.handle,
                program_id: identity.program_id,
                created_clsact: false,
            };
            if classify_inventory(&current, identity.hook, Some(&owned)) != TcState::Owned {
                return Err(TcIoError::IdentityMismatch);
            }
            send_request(
                TcRequest::DeleteFilter(encode_detach_request(identity)),
                NLM_F_REQUEST | NLM_F_ACK,
            )
            .await
        })
    }
}

async fn query_inventory(ifindex: u32) -> Result<TcInventory, TcIoError> {
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|_| failed("failed to open TC state query"))?;
    tokio::spawn(connection);

    let mut qdiscs = handle.qdisc().get().index(ifindex as i32).execute();
    let mut clsact_count = 0usize;
    while let Some(message) = qdiscs
        .try_next()
        .await
        .map_err(|_| failed("failed to query TC qdisc state"))?
    {
        if message.header.index != ifindex as i32 {
            return Err(failed("TC qdisc query returned a different interface"));
        }
        if message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, TcAttribute::Kind(kind) if kind == "clsact"))
        {
            clsact_count += 1;
        }
    }
    let clsact = match clsact_count {
        0 => TcClsactState::Absent,
        1 => TcClsactState::Present,
        _ => TcClsactState::Unknown,
    };
    if clsact != TcClsactState::Present {
        return Ok(TcInventory::empty(clsact));
    }

    let mut filters = query_filters(&handle, ifindex, TcHook::Ingress).await?;
    filters.extend(query_filters(&handle, ifindex, TcHook::Egress).await?);
    Ok(TcInventory::new(clsact, filters))
}

async fn query_filters(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    hook: TcHook,
) -> Result<Vec<TcFilterSlot>, TcIoError> {
    let request = handle.traffic_filter(ifindex as i32).get();
    let mut messages = match hook {
        TcHook::Ingress => request.ingress().execute(),
        TcHook::Egress => request.egress().execute(),
    };
    let mut filters = Vec::new();
    while let Some(message) = messages
        .try_next()
        .await
        .map_err(|_| failed("failed to query TC filter state"))?
    {
        filters.push(filter_slot(&message, ifindex, hook));
    }
    Ok(filters)
}

fn filter_slot(message: &TcMessage, ifindex: u32, hook: TcHook) -> TcFilterSlot {
    if message.header.index != ifindex as i32 || message.header.parent != parent_for(hook) {
        return TcFilterSlot::Unknown(hook);
    }
    let priority = (message.header.info >> 16) as u16;
    let filter_handle = message.header.handle.into();
    if priority == 0 || filter_handle == 0 {
        return TcFilterSlot::Unknown(hook);
    }
    let Some(kind) = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            TcAttribute::Kind(kind) => Some(kind.as_str()),
            _ => None,
        })
    else {
        return TcFilterSlot::Unknown(hook);
    };
    if kind != "bpf" {
        return TcFilterSlot::Other {
            hook,
            priority,
            handle: filter_handle,
        };
    }
    let program_ids: Vec<u32> = message
        .attributes
        .iter()
        .filter_map(|attribute| match attribute {
            TcAttribute::Options(options) => Some(options),
            _ => None,
        })
        .flatten()
        .filter_map(|option| match option {
            TcOption::Bpf(TcFilterBpfOption::ProgId(program_id)) if *program_id != 0 => {
                Some(*program_id)
            }
            _ => None,
        })
        .collect();
    match program_ids.as_slice() {
        [program_id] => TcFilterSlot::Bpf(TcKernelIdentity {
            ifindex,
            hook,
            priority,
            handle: filter_handle,
            program_id: *program_id,
        }),
        _ => TcFilterSlot::Unknown(hook),
    }
}

enum TcRequest {
    NewQdisc(TcMessage),
    NewFilter(TcMessage),
    DeleteFilter(TcMessage),
}

async fn send_request(request: TcRequest, flags: u16) -> Result<(), TcIoError> {
    let (connection, mut handle, _) =
        rtnetlink::new_connection().map_err(|_| failed("failed to open TC netlink operation"))?;
    tokio::spawn(connection);
    let route_message = match request {
        TcRequest::NewQdisc(message) => RouteNetlinkMessage::NewQueueDiscipline(message),
        TcRequest::NewFilter(message) => RouteNetlinkMessage::NewTrafficFilter(message),
        TcRequest::DeleteFilter(message) => RouteNetlinkMessage::DelTrafficFilter(message),
    };
    let mut message = NetlinkMessage::from(route_message);
    message.header.flags = flags;
    let mut responses = handle
        .request(message)
        .map_err(|_| failed("TC netlink request failed"))?;
    while let Some(response) = responses.next().await {
        if let NetlinkPayload::Error(error) = response.payload {
            return Err(netlink_error(rtnetlink::Error::NetlinkError(error)));
        }
    }
    Ok(())
}

fn netlink_error(error: rtnetlink::Error) -> TcIoError {
    if matches!(
        &error,
        rtnetlink::Error::NetlinkError(message)
            if message.to_io().raw_os_error() == Some(nix::libc::EEXIST)
    ) {
        TcIoError::Exists
    } else {
        failed("TC netlink operation failed")
    }
}

fn failed(message: &str) -> TcIoError {
    TcIoError::Failed(message.to_owned())
}

fn run_async<T, F, Fut>(operation: F) -> Result<T, TcIoError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, TcIoError>> + Send + 'static,
{
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| failed("failed to start TC runtime"))?
            .block_on(operation())
    })
    .join()
    .map_err(|_| failed("TC worker stopped unexpectedly"))?
}
