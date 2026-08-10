use thiserror::Error;

use crate::{
    LoadedBpfObject, MapPublisher, PortError, SafeTcPort,
    linux::tc::LoadedTc,
    ownership::{OwnedTc, TcHook},
};

pub const ACCEPTANCE_FAULT_ENV: &str = "L2_LOOP_ACCEPTANCE_FAULT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceFault {
    None,
    TcAttach,
    MapInitialize,
}

impl AcceptanceFault {
    pub fn parse(value: Option<&str>) -> Result<Self, AcceptanceFaultError> {
        match value {
            None => Ok(Self::None),
            Some("tc-attach") => Ok(Self::TcAttach),
            Some("map-initialize") => Ok(Self::MapInitialize),
            Some(_) => Err(AcceptanceFaultError),
        }
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
