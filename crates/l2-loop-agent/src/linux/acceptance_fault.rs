use l2_loop_common::{CounterValue, InterfaceConfig, StatsKey};
use thiserror::Error;

use crate::{
    LoadedBpfObject, MapPublisher, ObservationReadPurpose, ObservationReader, PortError,
    RawObservation, SafeTcPort,
    linux::{observation::ObservationIo, tc::LoadedTc},
    ownership::{OwnedMapPin, OwnedTc, OwnershipRecord, TcHook},
};

pub const ACCEPTANCE_FAULT_ENV: &str = "L2_LOOP_ACCEPTANCE_FAULT";
pub const ACCEPTANCE_DIAGNOSTICS_ENV: &str = "L2_LOOP_ACCEPTANCE_DIAGNOSTICS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceFault {
    None,
    TcAttach,
    MapInitialize,
    ObservationMapRead,
    RateSamplingMapRead,
}

impl AcceptanceFault {
    pub fn parse(value: Option<&str>) -> Result<Self, AcceptanceFaultError> {
        match value {
            None => Ok(Self::None),
            Some("tc-attach") => Ok(Self::TcAttach),
            Some("map-initialize") => Ok(Self::MapInitialize),
            Some("observation-map-read") => Ok(Self::ObservationMapRead),
            Some("rate-sampling-map-read") => Ok(Self::RateSamplingMapRead),
            Some(_) => Err(AcceptanceFaultError),
        }
    }
}

pub struct FaultInjectingObservationReader<R> {
    inner: R,
    fault: AcceptanceFault,
}

impl<R> FaultInjectingObservationReader<R> {
    pub const fn new(inner: R, fault: AcceptanceFault) -> Self {
        Self { inner, fault }
    }
}

impl<R> ObservationReader for FaultInjectingObservationReader<R>
where
    R: ObservationReader,
{
    fn read_exact(
        &mut self,
        ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError> {
        if self.fault == AcceptanceFault::RateSamplingMapRead
            && purpose == ObservationReadPurpose::BackgroundSample
        {
            return Err(PortError::coded_adapter(
                "OBS_MAP_UNAVAILABLE",
                "authorized isolated rate sampling map read failure",
            ));
        }
        self.inner.read_exact(ownership, purpose)
    }
}

pub struct FaultInjectingObservation<I> {
    inner: I,
    fault: AcceptanceFault,
}

impl<I> FaultInjectingObservation<I> {
    pub const fn new(inner: I, fault: AcceptanceFault) -> Self {
        Self { inner, fault }
    }
}

impl<I> ObservationIo for FaultInjectingObservation<I>
where
    I: ObservationIo,
{
    fn verify_hooks(&mut self, ownership: &OwnershipRecord) -> Result<(), PortError> {
        self.inner.verify_hooks(ownership)
    }

    fn fresh_map_id(&mut self, pin: &OwnedMapPin) -> Result<u32, PortError> {
        self.inner.fresh_map_id(pin)
    }

    fn read_config(
        &mut self,
        pin: &OwnedMapPin,
        ifindex: u32,
    ) -> Result<InterfaceConfig, PortError> {
        if self.fault == AcceptanceFault::ObservationMapRead {
            return Err(PortError::Adapter(
                "authorized isolated observation map read failure".to_owned(),
            ));
        }
        self.inner.read_config(pin, ifindex)
    }

    fn read_counter(
        &mut self,
        pin: &OwnedMapPin,
        key: &StatsKey,
    ) -> Result<Option<Vec<CounterValue>>, PortError> {
        self.inner.read_counter(pin, key)
    }

    fn current_keys(&mut self, pin: &OwnedMapPin) -> Result<Vec<StatsKey>, PortError> {
        self.inner.current_keys(pin)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid isolated acceptance fault stage")]
pub struct AcceptanceFaultError;

pub struct FaultInjectingTc<T> {
    inner: T,
    fault: AcceptanceFault,
}

impl<T> FaultInjectingTc<T> {
    pub const fn new(inner: T, fault: AcceptanceFault) -> Self {
        Self { inner, fault }
    }
}

impl<T> SafeTcPort for FaultInjectingTc<T>
where
    T: SafeTcPort,
{
    fn attach_explicit(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        loaded: LoadedTc,
    ) -> Result<OwnedTc, PortError> {
        if self.fault == AcceptanceFault::TcAttach {
            return Err(PortError::Adapter(
                "authorized isolated failure before TC attach".to_owned(),
            ));
        }
        self.inner.attach_explicit(ifindex, hook, loaded)
    }

    fn verify_exact(&mut self, owned: &OwnedTc) -> Result<(), PortError> {
        self.inner.verify_exact(owned)
    }

    fn detach_exact(&mut self, owned: &OwnedTc) -> Result<(), PortError> {
        self.inner.detach_exact(owned)
    }
}

pub struct FaultInjectingMaps<M> {
    inner: M,
    fault: AcceptanceFault,
}

impl<M> FaultInjectingMaps<M> {
    pub const fn new(inner: M, fault: AcceptanceFault) -> Self {
        Self { inner, fault }
    }
}

impl<M> MapPublisher for FaultInjectingMaps<M>
where
    M: MapPublisher,
{
    fn initialize_dependent(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError> {
        if self.fault == AcceptanceFault::MapInitialize {
            return Err(PortError::Adapter(
                "authorized isolated failure before map initialization".to_owned(),
            ));
        }
        self.inner.initialize_dependent(loaded, ifindex, generation)
    }

    fn publish_iface_config(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError> {
        self.inner.publish_iface_config(loaded, ifindex, generation)
    }

    fn rollback_initialized_exact(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError> {
        self.inner
            .rollback_initialized_exact(loaded, ifindex, generation)
    }
}
