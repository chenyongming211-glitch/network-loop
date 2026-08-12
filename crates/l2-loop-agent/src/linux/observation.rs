use aya::maps::{HashMap, Map, MapData, MapError, MapInfo, PerCpuHashMap};
use l2_loop_common::{
    ABI_VERSION, CounterValue, FingerprintKey, FingerprintValue, InterfaceConfig, StatsKey,
    agent_mode, hook_role, vlan_visibility,
};
use l2_loop_core::{
    ClassObservation, FingerprintEvidence, HookObservation, HookRole, ObservationCounters,
    TrafficClass, VlanVisibility,
};

use crate::{
    ObservationReadPurpose, ObservationReader, PortError, RawFingerprints, RawObservation,
    ownership::{
        OWNERSHIP_SCHEMA_VERSION, OwnedMapPin, OwnershipRecord, RunId, TcHook, TestPinRoot,
    },
};

use super::{
    tc::{RtnetlinkTcIo, TcIo, TcState, classify_inventory as classify_tc},
    xdp::{RtnetlinkXdpIo, XdpIo, XdpState, classify_inventory as classify_xdp},
};

const OBS_OWNERSHIP_MISMATCH: &str = "OBS_OWNERSHIP_MISMATCH";
const OBS_MAP_UNAVAILABLE: &str = "OBS_MAP_UNAVAILABLE";
const OBS_MAP_IDENTITY_MISMATCH: &str = "OBS_MAP_IDENTITY_MISMATCH";
const OBS_SNAPSHOT_FAILED: &str = "OBS_SNAPSHOT_FAILED";

const IFACE_CONFIG: &str = "IFACE_CONFIG";
const HOOK_STATS: &str = "HOOK_STATS";
const FINGERPRINTS: &str = "FINGERPRINTS";
const OBS_FINGERPRINT_UNAVAILABLE: &str = "OBS_FINGERPRINT_UNAVAILABLE";

pub trait ObservationIo: Send {
    fn verify_hooks(&mut self, ownership: &OwnershipRecord) -> Result<(), PortError>;
    fn fresh_map_id(&mut self, pin: &OwnedMapPin) -> Result<u32, PortError>;
    fn read_config(
        &mut self,
        pin: &OwnedMapPin,
        ifindex: u32,
    ) -> Result<InterfaceConfig, PortError>;
    fn read_counter(
        &mut self,
        pin: &OwnedMapPin,
        key: &StatsKey,
    ) -> Result<Option<Vec<CounterValue>>, PortError>;
    fn current_keys(&mut self, pin: &OwnedMapPin) -> Result<Vec<StatsKey>, PortError>;
    fn read_fingerprints(
        &mut self,
        pin: &OwnedMapPin,
    ) -> Result<Vec<FingerprintEvidence>, PortError>;
}

pub struct LinuxObservationReader<I> {
    io: I,
}

impl<I> LinuxObservationReader<I> {
    pub const fn new(io: I) -> Self {
        Self { io }
    }
}

impl<I: ObservationIo> ObservationReader for LinuxObservationReader<I> {
    fn read_exact(
        &mut self,
        ownership: &OwnershipRecord,
        purpose: ObservationReadPurpose,
    ) -> Result<RawObservation, PortError> {
        self.io.verify_hooks(ownership)?;
        validate_journal_identity(ownership)?;
        let (config_pin, stats_pin) = required_pins(ownership)?;

        let config_id = self.io.fresh_map_id(config_pin)?;
        let stats_id = self.io.fresh_map_id(stats_pin)?;
        if config_id != config_pin.map_id || stats_id != stats_pin.map_id {
            return Err(coded(
                OBS_MAP_IDENTITY_MISMATCH,
                "owned map identity changed",
            ));
        }
        let fingerprint_pin = match purpose {
            ObservationReadPurpose::Request => {
                let pin = select_pin(ownership, FINGERPRINTS)?;
                let map_id = self.io.fresh_map_id(pin).map_err(|_| {
                    coded(
                        OBS_MAP_IDENTITY_MISMATCH,
                        "owned fingerprint map identity is unavailable",
                    )
                })?;
                if map_id != pin.map_id {
                    return Err(coded(
                        OBS_MAP_IDENTITY_MISMATCH,
                        "owned fingerprint map identity changed",
                    ));
                }
                Some(pin)
            }
            ObservationReadPurpose::BackgroundSample => None,
        };

        let config = self.io.read_config(config_pin, ownership.ifindex)?;
        let vlan_visibility = validate_config(config, ownership)?;
        let current_keys = self.io.current_keys(stats_pin)?;
        validate_current_keys(&current_keys, ownership)?;

        let fingerprints = match fingerprint_pin {
            None => RawFingerprints::NotRequested,
            Some(fingerprint_pin) => match self.io.read_fingerprints(fingerprint_pin) {
                Ok(evidence) => RawFingerprints::Available(evidence),
                Err(_) => RawFingerprints::Unavailable {
                    code: OBS_FINGERPRINT_UNAVAILABLE,
                },
            },
        };

        Ok(RawObservation {
            ifindex: ownership.ifindex,
            generation: ownership.generation,
            vlan_visibility,
            hooks: [
                self.read_hook(
                    stats_pin,
                    ownership,
                    hook_role::EXTERNAL_XDP_INGRESS,
                    HookRole::ExternalXdpIngress,
                )?,
                self.read_hook(
                    stats_pin,
                    ownership,
                    hook_role::PHYSICAL_TC_EGRESS,
                    HookRole::PhysicalTcEgress,
                )?,
            ],
            fingerprints,
        })
    }
}

impl<I: ObservationIo> LinuxObservationReader<I> {
    fn read_hook(
        &mut self,
        stats_pin: &OwnedMapPin,
        ownership: &OwnershipRecord,
        raw_role: u8,
        role: HookRole,
    ) -> Result<HookObservation, PortError> {
        let keys = StatsKey::observation_keys(ownership.generation, ownership.ifindex, raw_role);
        Ok(HookObservation {
            role,
            total: self.read_aggregate(stats_pin, &keys[0])?,
            classes: [
                self.read_class(stats_pin, &keys[1], TrafficClass::L2Broadcast)?,
                self.read_class(stats_pin, &keys[2], TrafficClass::Ipv4Multicast)?,
                self.read_class(stats_pin, &keys[3], TrafficClass::Ipv6Multicast)?,
                self.read_class(stats_pin, &keys[4], TrafficClass::OtherL2Multicast)?,
                self.read_class(stats_pin, &keys[5], TrafficClass::LinkLocalControl)?,
                self.read_class(stats_pin, &keys[6], TrafficClass::UnicastOrUnclassified)?,
            ],
            parse_errors: self.read_aggregate(stats_pin, &keys[7])?,
        })
    }

    fn read_class(
        &mut self,
        stats_pin: &OwnedMapPin,
        key: &StatsKey,
        traffic_class: TrafficClass,
    ) -> Result<ClassObservation, PortError> {
        Ok(ClassObservation {
            traffic_class,
            counters: self.read_aggregate(stats_pin, key)?,
        })
    }

    fn read_aggregate(
        &mut self,
        stats_pin: &OwnedMapPin,
        key: &StatsKey,
    ) -> Result<ObservationCounters, PortError> {
        let values = self.io.read_counter(stats_pin, key)?.unwrap_or_default();
        values.into_iter().try_fold(
            ObservationCounters {
                packets: 0,
                bytes: 0,
            },
            |total, value| {
                total
                    .checked_add(ObservationCounters {
                        packets: value.packets,
                        bytes: value.bytes,
                    })
                    .map_err(|_| coded(OBS_SNAPSHOT_FAILED, "counter aggregation overflow"))
            },
        )
    }
}

fn validate_journal_identity(ownership: &OwnershipRecord) -> Result<(), PortError> {
    if ownership.schema_version != OWNERSHIP_SCHEMA_VERSION
        || ownership.abi_version != ABI_VERSION
        || ownership.ifindex == 0
        || ownership.generation == 0
    {
        return Err(coded(
            OBS_OWNERSHIP_MISMATCH,
            "ownership journal identity is invalid",
        ));
    }
    ownership.validate_owned_maps().map_err(|_| {
        coded(
            OBS_MAP_IDENTITY_MISMATCH,
            "owned map set does not match the journal contract",
        )
    })?;

    let Some(root) = ownership.map_pins.first().and_then(|pin| pin.path.parent()) else {
        return Err(coded(
            OBS_MAP_IDENTITY_MISMATCH,
            "owned map root is invalid",
        ));
    };
    let run_id = root
        .file_name()
        .and_then(|value| value.to_str())
        .and_then(|value| RunId::parse(value).ok())
        .ok_or_else(|| coded(OBS_MAP_IDENTITY_MISMATCH, "owned map root is invalid"))?;
    let expected_root = TestPinRoot::new(run_id)
        .map_err(|_| coded(OBS_MAP_IDENTITY_MISMATCH, "owned map root is invalid"))?;
    if expected_root.path() != root
        || ownership
            .map_pins
            .iter()
            .any(|pin| pin.path != root.join(&pin.name))
    {
        return Err(coded(
            OBS_MAP_IDENTITY_MISMATCH,
            "owned map paths do not match the isolated run",
        ));
    }
    Ok(())
}

fn required_pins(ownership: &OwnershipRecord) -> Result<(&OwnedMapPin, &OwnedMapPin), PortError> {
    let config = select_pin(ownership, IFACE_CONFIG)?;
    let stats = select_pin(ownership, HOOK_STATS)?;
    Ok((config, stats))
}

fn select_pin<'a>(
    ownership: &'a OwnershipRecord,
    required_name: &str,
) -> Result<&'a OwnedMapPin, PortError> {
    let mut matches = ownership
        .map_pins
        .iter()
        .filter(|pin| pin.name == required_name);
    let selected = matches.next().ok_or_else(|| {
        coded(
            OBS_MAP_IDENTITY_MISMATCH,
            "required owned map identity is missing",
        )
    })?;
    if matches.next().is_some() {
        return Err(coded(
            OBS_MAP_IDENTITY_MISMATCH,
            "required owned map identity is duplicated",
        ));
    }
    Ok(selected)
}

fn validate_config(
    config: InterfaceConfig,
    ownership: &OwnershipRecord,
) -> Result<VlanVisibility, PortError> {
    if config.interface_generation != ownership.generation
        || config.logical_ifindex != ownership.ifindex
    {
        return Err(coded(
            OBS_OWNERSHIP_MISMATCH,
            "interface configuration identity changed",
        ));
    }
    if config.mode != agent_mode::OBSERVE || config.role != hook_role::EXTERNAL_XDP_INGRESS {
        return Err(coded(
            OBS_MAP_UNAVAILABLE,
            "interface configuration is not observable",
        ));
    }
    match config.vlan_visibility {
        vlan_visibility::UNKNOWN => Ok(VlanVisibility::Unknown),
        vlan_visibility::VERIFIED_VISIBLE => Ok(VlanVisibility::VerifiedVisible),
        _ => Err(coded(
            OBS_MAP_UNAVAILABLE,
            "interface VLAN visibility is invalid",
        )),
    }
}

fn validate_current_keys(
    current: &[StatsKey],
    ownership: &OwnershipRecord,
) -> Result<(), PortError> {
    let approved = [
        hook_role::EXTERNAL_XDP_INGRESS,
        hook_role::PHYSICAL_TC_EGRESS,
    ]
    .into_iter()
    .flat_map(|role| StatsKey::observation_keys(ownership.generation, ownership.ifindex, role))
    .collect::<Vec<_>>();
    if current
        .iter()
        .any(|key| key.interface_generation == ownership.generation && !approved.contains(key))
    {
        return Err(coded(
            OBS_MAP_UNAVAILABLE,
            "statistics map contains an unsupported current-generation key",
        ));
    }
    Ok(())
}

pub struct AyaObservationIo {
    xdp: RtnetlinkXdpIo,
    tc: RtnetlinkTcIo,
}

impl AyaObservationIo {
    pub const fn new() -> Self {
        Self {
            xdp: RtnetlinkXdpIo,
            tc: RtnetlinkTcIo,
        }
    }
}

impl Default for AyaObservationIo {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationIo for AyaObservationIo {
    fn verify_hooks(&mut self, ownership: &OwnershipRecord) -> Result<(), PortError> {
        let xdp = ownership
            .xdp
            .as_ref()
            .ok_or_else(|| coded(OBS_OWNERSHIP_MISMATCH, "owned XDP hook identity is missing"))?;
        let [tc] = ownership.tc.as_slice() else {
            return Err(coded(
                OBS_OWNERSHIP_MISMATCH,
                "owned TC hook identity is invalid",
            ));
        };
        if xdp.ifindex != ownership.ifindex
            || tc.ifindex != ownership.ifindex
            || tc.hook != TcHook::Egress
        {
            return Err(coded(
                OBS_OWNERSHIP_MISMATCH,
                "owned hook identity does not match the journal",
            ));
        }

        let xdp_inventory = self
            .xdp
            .query(ownership.ifindex)
            .map_err(|_| coded(OBS_OWNERSHIP_MISMATCH, "XDP hook identity is unavailable"))?;
        if classify_xdp(&xdp_inventory, Some(xdp)) != XdpState::Owned {
            return Err(coded(OBS_OWNERSHIP_MISMATCH, "XDP hook identity changed"));
        }

        let tc_inventory = self
            .tc
            .query(ownership.ifindex)
            .map_err(|_| coded(OBS_OWNERSHIP_MISMATCH, "TC hook identity is unavailable"))?;
        if classify_tc(&tc_inventory, TcHook::Egress, Some(tc)) != TcState::Owned {
            return Err(coded(OBS_OWNERSHIP_MISMATCH, "TC hook identity changed"));
        }
        Ok(())
    }

    fn fresh_map_id(&mut self, pin: &OwnedMapPin) -> Result<u32, PortError> {
        MapInfo::from_pin(&pin.path)
            .map(|info| info.id())
            .map_err(|_| coded(OBS_MAP_UNAVAILABLE, "owned map identity is unavailable"))
    }

    fn read_config(
        &mut self,
        pin: &OwnedMapPin,
        ifindex: u32,
    ) -> Result<InterfaceConfig, PortError> {
        let map = open_map(pin)?;
        let configs = HashMap::<MapData, u32, InterfaceConfig>::try_from(map).map_err(|_| {
            coded(
                OBS_MAP_UNAVAILABLE,
                "interface configuration map is invalid",
            )
        })?;
        configs.get(&ifindex, 0).map_err(|_| {
            coded(
                OBS_MAP_UNAVAILABLE,
                "interface configuration entry is unavailable",
            )
        })
    }

    fn read_counter(
        &mut self,
        pin: &OwnedMapPin,
        key: &StatsKey,
    ) -> Result<Option<Vec<CounterValue>>, PortError> {
        let map = open_map(pin)?;
        let stats = PerCpuHashMap::<MapData, StatsKey, CounterValue>::try_from(map)
            .map_err(|_| coded(OBS_MAP_UNAVAILABLE, "statistics map is invalid"))?;
        match stats.get(key, 0) {
            Ok(values) => Ok(Some(values.to_vec())),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(_) => Err(coded(
                OBS_MAP_UNAVAILABLE,
                "statistics counter is unavailable",
            )),
        }
    }

    fn current_keys(&mut self, pin: &OwnedMapPin) -> Result<Vec<StatsKey>, PortError> {
        let map = open_map(pin)?;
        let stats = PerCpuHashMap::<MapData, StatsKey, CounterValue>::try_from(map)
            .map_err(|_| coded(OBS_MAP_UNAVAILABLE, "statistics map is invalid"))?;
        stats
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| coded(OBS_MAP_UNAVAILABLE, "statistics keys are unavailable"))
    }

    fn read_fingerprints(
        &mut self,
        pin: &OwnedMapPin,
    ) -> Result<Vec<FingerprintEvidence>, PortError> {
        let map = open_map(pin)?;
        let fingerprints = HashMap::<MapData, FingerprintKey, FingerprintValue>::try_from(map)
            .map_err(|_| coded(OBS_FINGERPRINT_UNAVAILABLE, "fingerprint map is invalid"))?;
        fingerprints
            .iter()
            .map(|entry| {
                entry
                    .map(|(key, value)| FingerprintEvidence { key, value })
                    .map_err(|_| {
                        coded(
                            OBS_FINGERPRINT_UNAVAILABLE,
                            "fingerprint evidence is unavailable",
                        )
                    })
            })
            .collect()
    }
}

fn open_map(pin: &OwnedMapPin) -> Result<Map, PortError> {
    let data = MapData::from_pin(&pin.path)
        .map_err(|_| coded(OBS_MAP_UNAVAILABLE, "owned map is unavailable"))?;
    Map::from_map_data(data).map_err(|_| coded(OBS_MAP_UNAVAILABLE, "owned map type is invalid"))
}

fn coded(code: &'static str, evidence: &'static str) -> PortError {
    PortError::coded_adapter(code, evidence)
}
