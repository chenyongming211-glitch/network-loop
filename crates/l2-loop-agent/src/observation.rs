use std::time::UNIX_EPOCH;

use l2_loop_core::{
    InterfaceName, InterfaceState, InterfaceStatus, OBSERVED_HOOK_COUNT, ObservationSnapshot,
};

use crate::{Clock, ObservationReader, PortError, RawObservation, ownership::OwnershipRecord};

const OBS_SESSION_NOT_FOUND: &str = "OBS_SESSION_NOT_FOUND";
const OBS_INTERFACE_MISMATCH: &str = "OBS_INTERFACE_MISMATCH";
const OBS_OWNERSHIP_MISMATCH: &str = "OBS_OWNERSHIP_MISMATCH";
const OBS_MAP_UNAVAILABLE: &str = "OBS_MAP_UNAVAILABLE";
const OBS_SNAPSHOT_FAILED: &str = "OBS_SNAPSHOT_FAILED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationError {
    code: &'static str,
    evidence: &'static str,
}

impl ObservationError {
    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn evidence(&self) -> &'static str {
        self.evidence
    }

    const fn new(code: &'static str, evidence: &'static str) -> Self {
        Self { code, evidence }
    }
}

pub struct ObservationService<R, C> {
    reader: R,
    clock: C,
}

impl<R, C> ObservationService<R, C>
where
    R: ObservationReader,
    C: Clock,
{
    pub const fn new(reader: R, clock: C) -> Self {
        Self { reader, clock }
    }

    pub fn observe(
        &mut self,
        requested: &InterfaceName,
        active_interface: &InterfaceName,
        ownership: &OwnershipRecord,
    ) -> Result<ObservationSnapshot, ObservationError> {
        if requested != active_interface {
            return Err(ObservationError::new(
                OBS_INTERFACE_MISMATCH,
                "requested interface does not match the active session",
            ));
        }

        let RawObservation {
            ifindex,
            generation,
            vlan_visibility,
            hooks,
        } = self.reader.read_exact(ownership).map_err(reader_error)?;
        if ifindex != ownership.ifindex || generation != ownership.generation {
            return Err(ObservationError::new(
                OBS_OWNERSHIP_MISMATCH,
                "observation identity does not match the ownership journal",
            ));
        }

        let captured_at_unix_ms = self
            .clock
            .wall_time()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(snapshot_error())?;

        ObservationSnapshot::new(
            requested.clone(),
            ifindex,
            generation,
            captured_at_unix_ms,
            vlan_visibility,
            hooks,
        )
        .map_err(|_| snapshot_error())
    }

    pub fn status(
        &mut self,
        requested: Option<&InterfaceName>,
        active_interface: Option<&InterfaceName>,
        ownership: Option<&OwnershipRecord>,
    ) -> Result<Vec<InterfaceStatus>, ObservationError> {
        let (active_interface, ownership) = match (active_interface, ownership) {
            (None, None) if requested.is_none() => return Ok(Vec::new()),
            (None, None) => {
                return Err(ObservationError::new(
                    OBS_SESSION_NOT_FOUND,
                    "no active isolated session matches the request",
                ));
            }
            (Some(active_interface), Some(ownership)) => (active_interface, ownership),
            _ => {
                return Err(ObservationError::new(
                    OBS_OWNERSHIP_MISMATCH,
                    "active session ownership is incomplete",
                ));
            }
        };
        let requested = requested.unwrap_or(active_interface);
        let snapshot = self.observe(requested, active_interface, ownership)?;
        let xdp_ingress = snapshot.hooks[0].total;
        let tc_egress = snapshot.hooks[OBSERVED_HOOK_COUNT - 1].total;

        Ok(vec![InterfaceStatus {
            interface: snapshot.interface,
            state: InterfaceState::Observing,
            generation: snapshot.generation,
            captured_at_unix_ms: snapshot.captured_at_unix_ms,
            health: snapshot.health,
            vlan_visibility: snapshot.vlan_visibility,
            xdp_ingress,
            tc_egress,
        }])
    }
}

fn reader_error(error: PortError) -> ObservationError {
    ObservationError::new(
        error.stable_code().unwrap_or(OBS_MAP_UNAVAILABLE),
        "observation reader failed",
    )
}

const fn snapshot_error() -> ObservationError {
    ObservationError::new(
        OBS_SNAPSHOT_FAILED,
        "observation snapshot construction failed",
    )
}
