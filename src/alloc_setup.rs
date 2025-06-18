//! Allocator setup for no_std + alloc on Cortex-M (ARM) using wee_alloc
// Place this in a file like src/alloc_setup.rs and include it in your lib.rs or main.rs

#![no_std]

extern crate alloc;
extern crate wee_alloc;

// Set wee_alloc as the global allocator
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Optionally, define a panic handler if you don't have one already
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
