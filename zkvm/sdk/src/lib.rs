//! Guest SDK for BVM-1 programs (docs/zkvm.md §5).
//!
//! Build guests for `riscv32im-unknown-none-elf`. The SDK provides:
//! - [`entry!`]: the program entry point (`_start`), which calls the guest's
//!   `main` and halts with exit code 0;
//! - the syscalls [`read`], [`write`], [`halt`], [`poseidon2`];
//! - a panic handler that halts with exit code 1 (no proof of success exists).
//!
//! `ECALL` can only be issued with inline assembly: [`ecall`] is the single
//! `unsafe` block of the SDK. It runs inside the virtual machine, never in a
//! node.

#![no_std]

pub const SYS_HALT: u32 = 0;
pub const SYS_READ: u32 = 1;
pub const SYS_WRITE: u32 = 2;
pub const SYS_POSEIDON2: u32 = 3;

/// Issues `ECALL` with `a7 = number`, `a0 = arg`; returns `a0`.
#[inline(always)]
pub fn ecall(number: u32, arg: u32) -> u32 {
    #[cfg(target_arch = "riscv32")]
    {
        let mut a0 = arg;
        // SAFETY: ECALL traps into the BVM-1 host, which reads a7/a0 and may
        // write a0 (and, for POSEIDON2, the 64 bytes at a0). No other state
        // is touched; the clobbers are declared.
        unsafe {
            core::arch::asm!("ecall", inout("a0") a0, in("a7") number, options(nostack));
        }
        a0
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (number, arg);
        unimplemented!("BVM-1 syscalls exist only on riscv32 guests")
    }
}

/// Reads the next private input word. Traps (no proof) at end of input.
#[inline(always)]
pub fn read() -> u32 {
    ecall(SYS_READ, 0)
}

/// Appends a word to the public output.
#[inline(always)]
pub fn write(value: u32) {
    ecall(SYS_WRITE, value);
}

/// Stops execution with a public exit code.
#[inline(always)]
pub fn halt(code: u32) -> ! {
    ecall(SYS_HALT, code);
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Applies the Poseidon2 permutation (BabyBear, width 16) in place. Every
/// word must be a canonical field element (< 2^31 − 2^27 + 1), else the
/// execution traps.
#[inline(always)]
pub fn poseidon2(state: &mut [u32; 16]) {
    ecall(SYS_POSEIDON2, state.as_mut_ptr() as u32);
}

/// Declares the guest entry point: `entry!(main)` with `fn main()`.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            $main();
            $crate::halt(0)
        }

        #[panic_handler]
        fn panic(_: &core::panic::PanicInfo) -> ! {
            $crate::halt(1)
        }
    };
}
