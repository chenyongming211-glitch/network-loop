use std::{cell::RefCell, rc::Rc, time::Duration};

use l2_loop_agent::{
    AgentService, HookHandle, HookManager, InterfaceIdentity, InterfaceResolver, PortError,
};
use l2_loop_core::{HookRole, InterfaceName, InterfaceState, PolicyRequest, TrafficClass};

#[test]
fn publishes_observe_config_only_after_both_hooks_verify() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let resolver = FakeResolver {
        events: events.clone(),
    };
    let hooks = FakeHooks::new(events.clone(), None);
    let mut service = AgentService::new(resolver, hooks);

    service.observe("bond0").unwrap();

    assert_eq!(service.state(), InterfaceState::Observing);
    assert_eq!(
        events.borrow().as_slice(),
        [
            "resolve",
            "attach_xdp",
            "attach_egress",
            "verify_xdp",
            "verify_egress",
            "publish_observe",
        ]
    );
}

#[test]
fn second_hook_failure_detaches_the_first_hook() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let resolver = FakeResolver {
        events: events.clone(),
    };
    let hooks = FakeHooks::new(events.clone(), Some(HookRole::PhysicalTcEgress));
    let mut service = AgentService::new(resolver, hooks);

    assert!(service.observe("bond0").is_err());
    assert_eq!(service.state(), InterfaceState::Error);
    assert_eq!(
        events.borrow().as_slice(),
        ["resolve", "attach_xdp", "attach_egress", "detach_xdp"]
    );
}

#[test]
fn policing_requires_observing_and_expiry_returns_to_observing() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let resolver = FakeResolver {
        events: events.clone(),
    };
    let hooks = FakeHooks::new(events, None);
    let mut service = AgentService::new(resolver, hooks);
    let policy = policy();

    assert!(service.apply_policy(&policy).is_err());
    service.observe("bond0").unwrap();
    service.apply_policy(&policy).unwrap();
    assert_eq!(service.state(), InterfaceState::Policing);

    service.expire_policy().unwrap();
    assert_eq!(service.state(), InterfaceState::Observing);
}

struct FakeResolver {
    events: Rc<RefCell<Vec<&'static str>>>,
}

impl InterfaceResolver for FakeResolver {
    fn resolve(&mut self, name: &InterfaceName) -> Result<InterfaceIdentity, PortError> {
        self.events.borrow_mut().push("resolve");
        Ok(InterfaceIdentity {
            name: name.clone(),
            ifindex: 3,
        })
    }
}

struct FakeHooks {
    events: Rc<RefCell<Vec<&'static str>>>,
    fail_on: Option<HookRole>,
}

impl FakeHooks {
    fn new(events: Rc<RefCell<Vec<&'static str>>>, fail_on: Option<HookRole>) -> Self {
        Self { events, fail_on }
    }
}

impl HookManager for FakeHooks {
    fn attach(
        &mut self,
        _interface: &InterfaceIdentity,
        role: HookRole,
    ) -> Result<HookHandle, PortError> {
        self.events.borrow_mut().push(match role {
            HookRole::ExternalXdpIngress => "attach_xdp",
            HookRole::PhysicalTcEgress => "attach_egress",
            _ => "attach_path",
        });
        if self.fail_on == Some(role) {
            Err(PortError::Adapter("attach failed".into()))
        } else {
            Ok(HookHandle {
                id: role.into(),
                role,
            })
        }
    }

    fn verify(&mut self, handle: HookHandle) -> Result<(), PortError> {
        self.events.borrow_mut().push(match handle.role {
            HookRole::ExternalXdpIngress => "verify_xdp",
            HookRole::PhysicalTcEgress => "verify_egress",
            _ => "verify_path",
        });
        Ok(())
    }

    fn detach(&mut self, handle: HookHandle) -> Result<(), PortError> {
        self.events.borrow_mut().push(match handle.role {
            HookRole::ExternalXdpIngress => "detach_xdp",
            HookRole::PhysicalTcEgress => "detach_egress",
            _ => "detach_path",
        });
        Ok(())
    }

    fn publish_observe(
        &mut self,
        _interface: &InterfaceIdentity,
        _generation: u64,
    ) -> Result<(), PortError> {
        self.events.borrow_mut().push("publish_observe");
        Ok(())
    }

    fn publish_policy(&mut self, _policy: &PolicyRequest) -> Result<(), PortError> {
        self.events.borrow_mut().push("publish_policy");
        Ok(())
    }

    fn clear_policy(&mut self) -> Result<(), PortError> {
        self.events.borrow_mut().push("clear_policy");
        Ok(())
    }
}

fn policy() -> PolicyRequest {
    PolicyRequest::new(
        "bond0",
        None,
        TrafficClass::L2Broadcast,
        Some(100),
        None,
        Duration::from_secs(60),
    )
    .unwrap()
}
