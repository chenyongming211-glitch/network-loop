use aya::maps::{HashMap, PerCpuHashMap, PerCpuValues};
use l2_loop_common::{
    CounterValue, InterfaceConfig, StatsKey, agent_mode, hook_role, vlan_visibility,
};

use crate::{
    linux::bpf_object::AyaObjectRuntime,
    ports::{LoadedBpfObject, MapPublisher, PortError},
};

const BPF_NOEXIST: u64 = 1;

pub struct AyaMapPublisher {
    runtime: AyaObjectRuntime,
}

impl AyaMapPublisher {
    pub fn new(runtime: AyaObjectRuntime) -> Self {
        Self { runtime }
    }
}

impl MapPublisher for AyaMapPublisher {
    fn initialize_dependent(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError> {
        if ifindex == 0 || generation == 0 {
            return Err(adapter("map initialization identity must be non-zero"));
        }
        let mut state = self.runtime.state.lock().map_err(lock_error)?;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| adapter("no Aya object is active"))?;
        verify_loaded(&active.loaded, loaded)?;
        if active.initialized.is_some() || active.published.is_some() {
            return Err(adapter("Aya maps are already initialized"));
        }

        let keys = stats_keys(ifindex, generation);
        let cpu_count = aya::util::nr_cpus()
            .map_err(|(_, error)| adapter(format!("failed to query CPU count: {error}")))?;
        let zero = CounterValue {
            packets: 0,
            bytes: 0,
        };
        let map = active
            .bpf
            .map_mut("HOOK_STATS")
            .ok_or_else(|| adapter("validated HOOK_STATS map disappeared"))?;
        let mut stats = PerCpuHashMap::<_, StatsKey, CounterValue>::try_from(map)
            .map_err(|error| adapter(format!("invalid HOOK_STATS map: {error}")))?;
        stats
            .insert(
                keys[0],
                PerCpuValues::try_from(vec![zero; cpu_count]).map_err(|error| {
                    adapter(format!("failed to allocate per-CPU counter values: {error}"))
                })?,
                BPF_NOEXIST,
            )
            .map_err(|error| adapter(format!("failed to initialize XDP stats: {error}")))?;
        if let Err(error) = stats.insert(
            keys[1],
            PerCpuValues::try_from(vec![zero; cpu_count]).map_err(|error| {
                adapter(format!("failed to allocate per-CPU counter values: {error}"))
            })?,
            BPF_NOEXIST,
        ) {
            let rollback = stats.remove(&keys[0]);
            return Err(adapter(format!(
                "failed to initialize TC stats: {error}; first entry rollback: {rollback:?}"
            )));
        }
        active.initialized = Some((ifindex, generation));
        Ok(())
    }

    fn publish_iface_config(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError> {
        let mut state = self.runtime.state.lock().map_err(lock_error)?;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| adapter("no Aya object is active"))?;
        verify_loaded(&active.loaded, loaded)?;
        if active.initialized != Some((ifindex, generation)) || active.published.is_some() {
            return Err(adapter(
                "dependent entries must match before IFACE_CONFIG publication",
            ));
        }
        let config = InterfaceConfig::new(
            generation,
            0,
            ifindex,
            agent_mode::OBSERVE,
            hook_role::EXTERNAL_XDP_INGRESS,
            vlan_visibility::UNKNOWN,
            0,
        );
        let map = active
            .bpf
            .map_mut("IFACE_CONFIG")
            .ok_or_else(|| adapter("validated IFACE_CONFIG map disappeared"))?;
        let mut configs = HashMap::<_, u32, InterfaceConfig>::try_from(map)
            .map_err(|error| adapter(format!("invalid IFACE_CONFIG map: {error}")))?;
        configs
            .insert(ifindex, config, BPF_NOEXIST)
            .map_err(|error| adapter(format!("failed to publish IFACE_CONFIG: {error}")))?;
        match configs.get(&ifindex, 0) {
            Ok(current) if current == config => {
                active.published = Some((ifindex, generation));
                Ok(())
            }
            verification => {
                let rollback = configs.remove(&ifindex);
                Err(adapter(format!(
                    "IFACE_CONFIG verification failed: {verification:?}; rollback: {rollback:?}"
                )))
            }
        }
    }

    fn rollback_initialized_exact(
        &mut self,
        loaded: &LoadedBpfObject,
        ifindex: u32,
        generation: u64,
    ) -> Result<(), PortError> {
        let mut state = self.runtime.state.lock().map_err(lock_error)?;
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| adapter("no Aya object is active"))?;
        verify_loaded(&active.loaded, loaded)?;
        let identity = (ifindex, generation);
        if active.initialized != Some(identity) {
            return Err(adapter("initialized map identity mismatch"));
        }

        if active.published == Some(identity) {
            let map = active
                .bpf
                .map_mut("IFACE_CONFIG")
                .ok_or_else(|| adapter("validated IFACE_CONFIG map disappeared"))?;
            let mut configs = HashMap::<_, u32, InterfaceConfig>::try_from(map)
                .map_err(|error| adapter(format!("invalid IFACE_CONFIG map: {error}")))?;
            let current = configs
                .get(&ifindex, 0)
                .map_err(|error| adapter(format!("failed to requery IFACE_CONFIG: {error}")))?;
            if current.interface_generation != generation || current.logical_ifindex != ifindex {
                return Err(adapter("fresh IFACE_CONFIG identity mismatch"));
            }
            configs
                .remove(&ifindex)
                .map_err(|error| adapter(format!("failed to remove IFACE_CONFIG: {error}")))?;
            active.published = None;
        } else if active.published.is_some() {
            return Err(adapter("published map identity mismatch"));
        }

        let keys = stats_keys(ifindex, generation);
        let map = active
            .bpf
            .map_mut("HOOK_STATS")
            .ok_or_else(|| adapter("validated HOOK_STATS map disappeared"))?;
        let mut stats = PerCpuHashMap::<_, StatsKey, CounterValue>::try_from(map)
            .map_err(|error| adapter(format!("invalid HOOK_STATS map: {error}")))?;
        for key in keys.iter().rev() {
            stats
                .get(key, 0)
                .map_err(|error| adapter(format!("failed to requery HOOK_STATS: {error}")))?;
            stats
                .remove(key)
                .map_err(|error| adapter(format!("failed to remove HOOK_STATS: {error}")))?;
        }
        active.initialized = None;
        Ok(())
    }
}

fn stats_keys(ifindex: u32, generation: u64) -> [StatsKey; 2] {
    [
        StatsKey::total(generation, ifindex, hook_role::EXTERNAL_XDP_INGRESS),
        StatsKey::total(generation, ifindex, hook_role::PHYSICAL_TC_EGRESS),
    ]
}

fn verify_loaded(
    active: &LoadedBpfObject,
    requested: &LoadedBpfObject,
) -> Result<(), PortError> {
    if active == requested {
        Ok(())
    } else {
        Err(adapter("loaded BPF object identity mismatch"))
    }
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> PortError {
    adapter("Aya runtime lock is poisoned")
}

fn adapter(message: impl Into<String>) -> PortError {
    PortError::Adapter(message.into())
}
