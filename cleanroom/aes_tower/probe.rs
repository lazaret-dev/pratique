#![forbid(unsafe_code)]
#[path = "../../src/crypto/aes_sbox_clean.rs"]
mod accepted;
mod sbox;

#[inline(never)]
fn accepted_sbox(q: &[u64; 8]) -> [u64; 8] {
    accepted::sbox(q)
}

#[inline(never)]
fn tower_sbox(q: &[u64; 8]) -> [u64; 8] {
    sbox::sbox(q)
}

fn main() {
    use std::hint::black_box;
    use std::time::Instant;
    for (label, function) in [
        ("accepted", accepted_sbox as fn(&[u64; 8]) -> [u64; 8]),
        ("tower", tower_sbox),
    ] {
        let mut samples = Vec::new();
        for _ in 0..9 {
            let mut q = black_box([0x0123_4567_89ab_cdef; 8]);
            let start = Instant::now();
            for _ in 0..1_000_000 {
                q = black_box(function(black_box(&q)));
            }
            samples.push(start.elapsed().as_secs_f64() * 1e3);
            black_box(q);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "{label}: median {:.3} ns per S-box call (64 lanes), min {:.3}",
            samples[4], samples[0]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_in_every_lane() {
        for byte in 0..256 {
            for lane in 0..64 {
                let mut input = [0; 8];
                for plane in 0..8 {
                    input[plane] = ((byte as u64 >> plane) & 1) << lane;
                }
                assert_eq!(
                    sbox::sbox(&input),
                    accepted::sbox(&input),
                    "byte {byte}, lane {lane}"
                );
            }
        }
    }

    #[test]
    fn deterministic_mixed_lanes() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for _ in 0..10_000 {
            let mut q = [0; 8];
            for plane in &mut q {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *plane = state;
            }
            assert_eq!(sbox::sbox(&q), accepted::sbox(&q));
        }
    }
}
