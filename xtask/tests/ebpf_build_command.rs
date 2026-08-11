use xtask::ebpf::{EBPF_CARGO_TOOLCHAIN, build_ebpf_args};

#[test]
fn ebpf_build_uses_the_dated_nightly_and_workspace_lock() {
    assert_eq!(EBPF_CARGO_TOOLCHAIN, "+nightly-2026-08-10");
    assert_eq!(
        build_ebpf_args(),
        [
            "+nightly-2026-08-10",
            "build",
            "--locked",
            "-Z",
            "build-std=core",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "--package",
            "l2-loop-ebpf",
        ]
    );
}
