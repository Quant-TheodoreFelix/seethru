#![no_std]

use core::ptr;

pub struct Vault {
    key: [u32; 8],
}

impl Vault {
    pub fn fill(&mut self, seed: &[u32; 8]) {
        self.key = *seed;
    }

    #[inline(never)]
    pub fn slot(&self, modulus: u32) -> u32 {
        let mut sum = 0u32;
        for part in self.key.iter() {
            sum = sum.wrapping_add(*part % modulus);
        }
        sum
    }

    pub fn close(&mut self) {
        for part in self.key.iter_mut() {
            unsafe { ptr::write_volatile(part, 0) };
        }
    }
}

pub fn open_once(vault: &mut Vault, modulus: u32) -> u32 {
    let slot = vault.slot(modulus);
    vault.close();
    slot
}

#[inline(never)]
pub fn bucket(public: &[u32; 8], modulus: u32) -> u32 {
    let mut sum = 0u32;
    for part in public.iter() {
        sum = sum.wrapping_add(*part % modulus);
    }
    sum
}
