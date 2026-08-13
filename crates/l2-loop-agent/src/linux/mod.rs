//! Pure Linux snapshot parsing used by the read-only preflight inspector.

pub mod acceptance_fault;
pub mod bond;
pub mod bpf_inventory;
pub mod bpf_object;
pub mod cleanup;
pub mod deployment_fs;
pub mod deployment_platform;
pub mod deployment_unit;
pub mod inspector;
pub mod interface;
pub mod limits;
pub mod maps;
pub mod observation;
pub mod tc;
pub mod topology;
pub mod xdp;
