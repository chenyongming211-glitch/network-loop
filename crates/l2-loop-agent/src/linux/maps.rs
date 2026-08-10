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
        let mut inserted = Vec::with_capacity(keys.len());
        for key in keys {
            let values = match PerCpuValues::try_from(vec![zero; cpu_count]) {
                Ok(values) => values,
                Err(error) => {
                    let rollback = inserted
                        .iter()
                        .rev()
                        .map(|inserted_key| stats.remove(inserted_key))
                        .collect::<Vec<_>>();
                    return Err(adapter(format!(
                        "failed to allocate per-CPU counter values: {error}; rollback: {rollback:?}"
                    )));
                }
            };
            if let Err(error) = stats.insert(key, values, BPF_NOEXIST) {
                let rollback = inserted
                    .iter()
                    .rev()
                    .map(|inserted_key| stats.remove(inserted_key))
                    .collect::<Vec<_>>();
                return Err(adapter(format!(
                    "failed to initialize passive stats: {error}; rollback: {rollback:?}"
                )));
            }
            inserted.push(key);
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
        }
        for key in keys.iter().rev() {
            stats
                .remove(key)
                .map_err(|error| adapter(format!("failed to remove HOOK_STATS: {error}")))?;
        }
        active.initialized = None;
        Ok(())
    }
}

fn stats_keys(ifindex: u32, generation: u64) -> [StatsKey; 16] {
    let xdp = StatsKey::observation_keys(generation, ifindex, hook_role::EXTERNAL_XDP_INGRESS);
    let tc = StatsKey::observation_keys(generation, ifindex, hook_role::PHYSICAL_TC_EGRESS);
    [
        xdp[0], xdp[1], xdp[2], xdp[3], xdp[4], xdp[5], xdp[6], xdp[7], tc[0], tc[1], tc[2], tc[3],
        tc[4], tc[5], tc[6], tc[7],
    ]
}

fn verify_loaded(active: &LoadedBpfObject, requested: &LoadedBpfObject) -> Result<(), PortError> {
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

#[cfg(test)]
mod tests {
    use super::stats_keys;
    use l2_loop_common::{StatsKey, hook_role};

    #[test]
    fn observation_key_set_is_initialized_and_removed_exactly() {
        let xdp = StatsKey::observation_keys(7, 41, hook_role::EXTERNAL_XDP_INGRESS);
        let tc = StatsKey::observation_keys(7, 41, hook_role::PHYSICAL_TC_EGRESS);
        let expected = xdp.into_iter().chain(tc).collect::<Vec<_>>();
        let actual = stats_keys(41, 7).into_iter().collect::<Vec<_>>();

        assert_eq!(expected.len(), 16);
        assert_eq!(actual, expected);
        assert_eq!(
            stats_keys(41, 7).into_iter().rev().collect::<Vec<_>>(),
            expected.into_iter().rev().collect::<Vec<_>>(),
        );
    }
}
