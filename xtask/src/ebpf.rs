pub const EBPF_CARGO_TOOLCHAIN: &str = "+nightly-2026-08-10";

pub const fn build_ebpf_args() -> [&'static str; 10] {
    [
        EBPF_CARGO_TOOLCHAIN,
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
}
