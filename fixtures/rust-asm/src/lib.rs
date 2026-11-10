#![no_std]

use core::arch::asm;
use core::ptr;

pub struct Key {
    words: [u32; 4],
}

impl Key {
    pub fn close(&mut self) {
        for word in self.words.iter_mut() {
            unsafe { ptr::write_volatile(word, 0) };
        }
    }
}

#[inline(never)]
pub fn reduce(key: &mut Key, modulus: u32) -> u32 {
    let value = key.words[0];
    let quotient: u32;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("xor edx, edx", "div {m:e}", m = in(reg) modulus, inout("eax") value => quotient, out("edx") _, options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("udiv {q:w}, {v:w}, {m:w}", q = out(reg) quotient, v = in(reg) value, m = in(reg) modulus, options(nomem, nostack, pure));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        quotient = value.wrapping_div(modulus | 1);
    }
    key.close();
    quotient
}

#[inline(never)]
pub fn spin(count: usize) -> usize {
    let mut left = count | 1;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("2:", "dec {n}", "jnz 2b", n = inout(reg) left, options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("2:", "subs {n}, {n}, #1", "b.ne 2b", n = inout(reg) left, options(nomem, nostack));
    }
    left
}

#[inline(never)]
pub fn settle() {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe {
        asm!("nop", options(nomem, nostack, preserves_flags));
    }
}

#[inline(never)]
pub fn share(public: &[u32; 4], modulus: u32) -> u32 {
    public[0] % modulus
}
