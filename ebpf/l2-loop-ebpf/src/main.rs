#![no_std]
#![no_main]

#[cfg(feature = "diagnostics")]
compile_error!("diagnostic features must never build the ordinary product binary");

mod maps;
mod programs;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
