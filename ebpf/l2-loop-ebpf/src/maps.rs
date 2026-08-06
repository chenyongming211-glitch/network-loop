use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, PerCpuHashMap},
};
use l2_loop_common::{
    CounterValue, FingerprintKey, FingerprintValue, InterfaceConfig, PolicyKey, ProbeKey,
    ProbeRegistration, RatePolicy, StatsKey,
};

#[map]
pub static IFACE_CONFIG: HashMap<u32, InterfaceConfig> = HashMap::with_max_entries(64, 0);

#[map]
pub static HOOK_STATS: PerCpuHashMap<StatsKey, CounterValue> =
    PerCpuHashMap::with_max_entries(4096, 0);

#[map]
pub static FINGERPRINTS: LruHashMap<FingerprintKey, FingerprintValue> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
pub static PROBE_REGISTRY: HashMap<ProbeKey, ProbeRegistration> = HashMap::with_max_entries(128, 0);

#[map]
pub static PROBE_STATS: PerCpuHashMap<ProbeKey, CounterValue> =
    PerCpuHashMap::with_max_entries(128, 0);

#[map]
pub static RATE_POLICY: HashMap<PolicyKey, RatePolicy> = HashMap::with_max_entries(256, 0);
