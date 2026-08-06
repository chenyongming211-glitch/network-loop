use csmp_loop_core::{
    DomainError, HookRole, InterfaceName, InterfaceState, PolicyRequest,
};
use thiserror::Error;

use crate::ports::{HookHandle, HookManager, InterfaceResolver, PortError};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Port(#[from] PortError),
    #[error("operation is not valid while interface is {0:?}")]
    InvalidState(InterfaceState),
}

pub struct AgentService<R, H> {
    resolver: R,
    hooks: H,
    state: InterfaceState,
    generation: u64,
}

impl<R, H> AgentService<R, H>
where
    R: InterfaceResolver,
    H: HookManager,
{
    pub const fn new(resolver: R, hooks: H) -> Self {
        Self {
            resolver,
            hooks,
            state: InterfaceState::Detached,
            generation: 0,
        }
    }

    pub const fn state(&self) -> InterfaceState {
        self.state
    }

    pub fn observe(&mut self, interface: impl Into<String>) -> Result<(), ServiceError> {
        if self.state != InterfaceState::Detached {
            return Err(ServiceError::InvalidState(self.state));
        }

        let interface = InterfaceName::new(interface)?;
        self.state = self.state.transition(InterfaceState::Attaching)?;

        let identity = match self.resolver.resolve(&interface) {
            Ok(identity) => identity,
            Err(error) => return self.fail(error),
        };
        let ingress = match self
            .hooks
            .attach(&identity, HookRole::ExternalXdpIngress)
        {
            Ok(handle) => handle,
            Err(error) => return self.fail(error),
        };
        let egress = match self.hooks.attach(&identity, HookRole::PhysicalTcEgress) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = self.hooks.detach(ingress);
                return self.fail(error);
            }
        };

        if let Err(error) = self.verify_both(ingress, egress) {
            self.detach_both(ingress, egress);
            return self.fail(error);
        }

        let generation = self.generation.saturating_add(1).max(1);
        if let Err(error) = self.hooks.publish_observe(&identity, generation) {
            self.detach_both(ingress, egress);
            return self.fail(error);
        }

        self.generation = generation;
        self.state = self.state.transition(InterfaceState::Observing)?;
        Ok(())
    }

    pub fn apply_policy(&mut self, policy: &PolicyRequest) -> Result<(), ServiceError> {
        if self.state != InterfaceState::Observing {
            return Err(ServiceError::InvalidState(self.state));
        }
        self.hooks.publish_policy(policy)?;
        self.state = self.state.transition(InterfaceState::Policing)?;
        Ok(())
    }

    pub fn expire_policy(&mut self) -> Result<(), ServiceError> {
        if self.state != InterfaceState::Policing {
            return Err(ServiceError::InvalidState(self.state));
        }
        self.hooks.clear_policy()?;
        self.state = self.state.transition(InterfaceState::Observing)?;
        Ok(())
    }

    fn verify_both(
        &mut self,
        ingress: HookHandle,
        egress: HookHandle,
    ) -> Result<(), PortError> {
        self.hooks.verify(ingress)?;
        self.hooks.verify(egress)
    }

    fn detach_both(&mut self, ingress: HookHandle, egress: HookHandle) {
        let _ = self.hooks.detach(egress);
        let _ = self.hooks.detach(ingress);
    }

    fn fail<T>(&mut self, error: PortError) -> Result<T, ServiceError> {
        self.state = InterfaceState::Error;
        Err(ServiceError::Port(error))
    }
}
