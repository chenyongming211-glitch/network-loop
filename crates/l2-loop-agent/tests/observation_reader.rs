#![cfg(target_os = "linux")]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use l2_loop_agent::{
    ObservationReader, PortError,
    linux::observation::{LinuxObservationReader, ObservationIo},
    ownership::{
        OWNED_MAP_NAMES, OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnedTc, OwnedXdp, OwnershipRecord,
        TcHook, XdpAttachMode,
    },
};
use l2_loop_common::{
    ABI_VERSION, CounterValue, InterfaceConfig, StatsKey, agent_mode, hook_role, traffic_class,
    vlan_visibility,
};
use l2_loop_core::{HookRole, ObservationCounters, TrafficClass, VlanVisibility};

const IFINDEX: u32 = 41;
const GENERATION: u64 = 7;
const IFACE_CONFIG: &str = "IFACE_CONFIG";
const HOOK_STATS: &str = "HOOK_STATS";
const RUN_ROOT: &str = "/sys/fs/bpf/l2-loop/test/0123456789abcdef0123456789abcdef";

#[test]
fn changed_hook_identity_is_refused_before_map_io() {
    let io = FakeIo::complete().hook_error(PortError::coded_adapter(
        "OBS_OWNERSHIP_MISMATCH",
        "hook identity changed",
    ));
    let events = io.events();

    let error = LinuxObservationReader::new(io)
        .read_exact(&ownership())
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_OWNERSHIP_MISMATCH"));
    assert_eq!(events.lock().unwrap().as_slice(), ["verify_hooks"]);
}

#[test]
fn changed_hook_stats_pin_is_refused_before_content_reads() {
    let io = FakeIo::complete().map_id(HOOK_STATS, 999);
    let events = io.events();

    let error = LinuxObservationReader::new(io)
        .read_exact(&ownership())
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_MAP_IDENTITY_MISMATCH"));
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|event| !event.starts_with("read_"))
    );
}

#[test]
fn incomplete_owned_map_set_is_refused_before_map_io() {
    let mut record = ownership();
    record.map_pins.retain(|pin| pin.name != HOOK_STATS);
    let io = FakeIo::complete();
    let events = io.events();

    let error = LinuxObservationReader::new(io)
        .read_exact(&record)
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_MAP_IDENTITY_MISMATCH"));
    assert_eq!(events.lock().unwrap().as_slice(), ["verify_hooks"]);
}

#[test]
fn duplicate_required_map_name_is_refused_before_map_io() {
    let mut record = ownership();
    record.map_pins[2].name = HOOK_STATS.to_owned();
    record.map_pins[2].path = pin(HOOK_STATS);
    let io = FakeIo::complete();
    let events = io.events();

    let error = LinuxObservationReader::new(io)
        .read_exact(&record)
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_MAP_IDENTITY_MISMATCH"));
    assert_eq!(events.lock().unwrap().as_slice(), ["verify_hooks"]);
}

#[test]
fn per_cpu_values_are_aggregated_with_checked_addition() {
    let io = FakeIo::complete()
        .counter(total_xdp(), vec![counter(2, 120), counter(3, 180)])
        .counter(class_xdp(traffic_class::L2_BROADCAST), vec![counter(1, 60)])
        .counter(total_tc(), vec![counter(4, 240)]);

    let raw = LinuxObservationReader::new(io)
        .read_exact(&ownership())
        .unwrap();

    assert_eq!(raw.ifindex, IFINDEX);
    assert_eq!(raw.generation, GENERATION);
    assert_eq!(raw.hooks[0].role, HookRole::ExternalXdpIngress);
    assert_eq!(raw.hooks[0].total, counters(5, 300));
    assert_eq!(
        raw.hooks[0].classes[0].traffic_class,
        TrafficClass::L2Broadcast
    );
    assert_eq!(raw.hooks[0].classes[0].counters, counters(1, 60));
    assert_eq!(raw.hooks[1].role, HookRole::PhysicalTcEgress);
    assert_eq!(raw.hooks[1].total, counters(4, 240));
}

#[test]
fn absent_fixed_counter_key_is_reported_as_zero() {
    let raw = LinuxObservationReader::new(FakeIo::complete())
        .read_exact(&ownership())
        .unwrap();

    for hook in raw.hooks {
        assert_eq!(hook.total, counters(0, 0));
        assert_eq!(hook.parse_errors, counters(0, 0));
        assert!(
            hook.classes
                .iter()
                .all(|class| class.counters == counters(0, 0))
        );
    }
}

#[test]
fn unexpected_current_generation_key_is_refused_before_counter_reads() {
    let unexpected = StatsKey::classified(
        GENERATION,
        IFINDEX,
        hook_role::TEMPORARY_PATH_INGRESS,
        traffic_class::L2_BROADCAST,
    );
    let io = FakeIo::complete().keys(approved_keys().into_iter().chain([unexpected]).collect());
    let events = io.events();

    let error = LinuxObservationReader::new(io)
        .read_exact(&ownership())
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_MAP_UNAVAILABLE"));
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|event| !event.starts_with("read_counter:"))
    );
}

#[test]
fn non_current_config_generation_is_an_ownership_mismatch() {
    let config = InterfaceConfig::new(
        GENERATION + 1,
        0,
        IFINDEX,
        agent_mode::OBSERVE,
        hook_role::EXTERNAL_XDP_INGRESS,
        vlan_visibility::UNKNOWN,
        0,
    );

    let error = LinuxObservationReader::new(FakeIo::complete().config(config))
        .read_exact(&ownership())
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_OWNERSHIP_MISMATCH"));
}

#[test]
fn invalid_interface_config_mode_is_refused() {
    let config = InterfaceConfig::new(
        GENERATION,
        0,
        IFINDEX,
        agent_mode::POLICE,
        hook_role::EXTERNAL_XDP_INGRESS,
        vlan_visibility::UNKNOWN,
        0,
    );

    let error = LinuxObservationReader::new(FakeIo::complete().config(config))
        .read_exact(&ownership())
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_MAP_UNAVAILABLE"));
}

#[test]
fn per_cpu_aggregation_overflow_is_a_snapshot_failure() {
    let io = FakeIo::complete().counter(total_xdp(), vec![counter(u64::MAX, 1), counter(1, 1)]);

    let error = LinuxObservationReader::new(io)
        .read_exact(&ownership())
        .unwrap_err();

    assert_eq!(error.stable_code(), Some("OBS_SNAPSHOT_FAILED"));
}

#[test]
fn supported_vlan_visibility_values_are_converted() {
    for (raw_visibility, expected) in [
        (vlan_visibility::UNKNOWN, VlanVisibility::Unknown),
        (
            vlan_visibility::VERIFIED_VISIBLE,
            VlanVisibility::VerifiedVisible,
        ),
    ] {
        let config = InterfaceConfig::new(
            GENERATION,
            0,
            IFINDEX,
            agent_mode::OBSERVE,
            hook_role::EXTERNAL_XDP_INGRESS,
            raw_visibility,
            0,
        );

        let raw = LinuxObservationReader::new(FakeIo::complete().config(config))
            .read_exact(&ownership())
            .unwrap();

        assert_eq!(raw.vlan_visibility, expected);
    }
}

#[derive(Clone)]
struct FakeIo {
    hook_error: Option<PortError>,
    map_ids: Vec<(String, u32)>,
    config: InterfaceConfig,
    counters: Vec<(StatsKey, Vec<CounterValue>)>,
    keys: Vec<StatsKey>,
    events: Arc<Mutex<Vec<String>>>,
}

impl FakeIo {
    fn complete() -> Self {
        Self {
            hook_error: None,
            map_ids: vec![(IFACE_CONFIG.to_owned(), 301), (HOOK_STATS.to_owned(), 302)],
            config: InterfaceConfig::new(
                GENERATION,
                0,
                IFINDEX,
                agent_mode::OBSERVE,
                hook_role::EXTERNAL_XDP_INGRESS,
                vlan_visibility::UNKNOWN,
                0,
            ),
            counters: Vec::new(),
            keys: approved_keys(),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn hook_error(mut self, error: PortError) -> Self {
        self.hook_error = Some(error);
        self
    }

    fn map_id(mut self, name: &str, map_id: u32) -> Self {
        self.map_ids
            .iter_mut()
            .find(|(candidate, _)| candidate == name)
            .unwrap()
            .1 = map_id;
        self
    }

    fn config(mut self, config: InterfaceConfig) -> Self {
        self.config = config;
        self
    }

    fn counter(mut self, key: StatsKey, values: Vec<CounterValue>) -> Self {
        self.counters.push((key, values));
        self
    }

    fn keys(mut self, keys: Vec<StatsKey>) -> Self {
        self.keys = keys;
        self
    }

    fn events(&self) -> Arc<Mutex<Vec<String>>> {
        self.events.clone()
    }

    fn record(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }
}

impl ObservationIo for FakeIo {
    fn verify_hooks(&mut self, _ownership: &OwnershipRecord) -> Result<(), PortError> {
        self.record("verify_hooks");
        match &self.hook_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn fresh_map_id(&mut self, pin: &OwnedMapPin) -> Result<u32, PortError> {
        self.record(format!("map_id:{}", pin.name));
        self.map_ids
            .iter()
            .find_map(|(name, map_id)| (name == &pin.name).then_some(*map_id))
            .ok_or_else(|| PortError::Adapter("map identity unavailable".to_owned()))
    }

    fn read_config(
        &mut self,
        pin: &OwnedMapPin,
        _ifindex: u32,
    ) -> Result<InterfaceConfig, PortError> {
        self.record(format!("read_config:{}", pin.name));
        Ok(self.config)
    }

    fn read_counter(
        &mut self,
        pin: &OwnedMapPin,
        key: &StatsKey,
    ) -> Result<Option<Vec<CounterValue>>, PortError> {
        self.record(format!("read_counter:{}", pin.name));
        Ok(self
            .counters
            .iter()
            .find_map(|(candidate, values)| (candidate == key).then(|| values.clone())))
    }

    fn current_keys(&mut self, pin: &OwnedMapPin) -> Result<Vec<StatsKey>, PortError> {
        self.record(format!("read_keys:{}", pin.name));
        Ok(self.keys.clone())
    }
}

fn ownership() -> OwnershipRecord {
    OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        abi_version: ABI_VERSION,
        generation: GENERATION,
        ifindex: IFINDEX,
        xdp: Some(OwnedXdp {
            ifindex: IFINDEX,
            mode: XdpAttachMode::Native,
            program_id: 101,
            program_tag: [1; 8],
            link_id: Some(201),
        }),
        tc: vec![OwnedTc {
            ifindex: IFINDEX,
            hook: TcHook::Egress,
            priority: 49_600,
            handle: 0x4c32_0002,
            program_id: 102,
            created_clsact: true,
        }],
        map_pins: OWNED_MAP_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| OwnedMapPin::new(*name, pin(name), 301 + index as u32).unwrap())
            .collect(),
        created_at_unix_seconds: 1_787_000_000,
    }
}

fn approved_keys() -> Vec<StatsKey> {
    [
        hook_role::EXTERNAL_XDP_INGRESS,
        hook_role::PHYSICAL_TC_EGRESS,
    ]
    .into_iter()
    .flat_map(|role| StatsKey::observation_keys(GENERATION, IFINDEX, role))
    .collect()
}

fn total_xdp() -> StatsKey {
    StatsKey::total(GENERATION, IFINDEX, hook_role::EXTERNAL_XDP_INGRESS)
}

fn total_tc() -> StatsKey {
    StatsKey::total(GENERATION, IFINDEX, hook_role::PHYSICAL_TC_EGRESS)
}

fn class_xdp(class: u8) -> StatsKey {
    StatsKey::classified(GENERATION, IFINDEX, hook_role::EXTERNAL_XDP_INGRESS, class)
}

const fn counter(packets: u64, bytes: u64) -> CounterValue {
    CounterValue { packets, bytes }
}

const fn counters(packets: u64, bytes: u64) -> ObservationCounters {
    ObservationCounters { packets, bytes }
}

fn pin(name: &str) -> PathBuf {
    Path::new(RUN_ROOT).join(name)
}
