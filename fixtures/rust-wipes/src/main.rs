use std::io::Read;

#[inline(never)]
fn mix(key: &[u8; 32], input: &[u8]) -> u8 {
    let mut out = 0u8;
    for (a, b) in key.iter().zip(input) {
        out ^= a.wrapping_mul(*b);
    }
    out
}

#[inline(never)]
fn removed(input: &[u8]) -> u8 {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(input) {
        *slot = byte.wrapping_add(7);
    }
    let out = mix(&key, input);
    key.fill(0);
    out
}

#[inline(never)]
fn kept(input: &[u8]) -> u8 {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(input) {
        *slot = byte.wrapping_add(9);
    }
    let out = mix(&key, input);
    for slot in key.iter_mut() {
        unsafe { std::ptr::write_volatile(slot, 0) };
    }
    out
}

#[inline(never)]
fn clear(buffer: &mut [u8]) {
    buffer.fill(0);
}

fn main() {
    let mut input = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut input);
    let first = removed(&input);
    let second = kept(&input);
    clear(&mut input);
    let left: u32 = input.iter().map(|byte| u32::from(*byte)).sum();
    println!("{first} {second} {left}");
}
