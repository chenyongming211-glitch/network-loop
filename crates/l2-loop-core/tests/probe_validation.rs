use std::time::Duration;

use l2_loop_core::{ProbeRequest, ProbeScope};

#[test]
fn accepts_one_safe_probe_request() {
    let request = ProbeRequest::new(
        "bond0",
        ProbeScope::External,
        Some(100),
        Duration::from_secs(2),
    )
    .unwrap();

    assert_eq!(request.interface().as_str(), "bond0");
    assert_eq!(request.scope(), ProbeScope::External);
    assert_eq!(request.vlan(), Some(100));
    assert_eq!(request.timeout(), Duration::from_secs(2));
}

#[test]
fn validates_interface_vlan_and_timeout() {
    assert!(probe("", None, 2_000).is_err());
    assert!(probe("bond0", Some(0), 2_000).is_err());
    assert!(probe("bond0", Some(1), 2_000).is_ok());
    assert!(probe("bond0", Some(4094), 2_000).is_ok());
    assert!(probe("bond0", Some(4095), 2_000).is_err());
    assert!(probe("bond0", None, 99).is_err());
    assert!(probe("bond0", None, 100).is_ok());
    assert!(probe("bond0", None, 30_000).is_ok());
    assert!(probe("bond0", None, 30_001).is_err());
}

fn probe(
    interface: &str,
    vlan: Option<u16>,
    timeout_millis: u64,
) -> Result<ProbeRequest, l2_loop_core::DomainError> {
    ProbeRequest::new(
        interface,
        ProbeScope::Internal,
        vlan,
        Duration::from_millis(timeout_millis),
    )
}
