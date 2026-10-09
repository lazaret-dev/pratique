//! SHA-256 and SHA-512 block functions on the CPU's own instructions (B-103): ARMv8's SHA-256 instructions (`sha2`)
//! and ARMv8.2's SHA-512 ones (`sha3` in Rust's names), and x86-64's SHA extensions (SHA-256 only; there are none for
//! SHA-512 on the CPUs this was written for).
//!
//! Found at run time, like the AES instructions (`aes_hw`), and offered to `sha2` only after a self-test: each block
//! function hashes a few hundred blocks of fixed input alongside the portable code, and one that disagrees is not used.
//! With `--cfg pratique_portable` nothing here is compiled in and `detect` offers none.
//!
//! The instructions take the same time whatever the data (they are among those ARM's data-independent timing mode
//! covers, which HMAC sets around its keys), so they keep the constant-time property of the portable code.

use super::sha2::{self, Accel};

/// What `sha2` uses: the hardware block functions this CPU has, each checked against the portable one.
pub(super) fn detect() -> Accel {
    let mut a = hardware();
    if let Some(f) = a.sha256 {
        if !agrees256(f) {
            a.sha256 = None;
        }
    }
    if let Some(f) = a.sha512 {
        if !agrees512(f) {
            a.sha512 = None;
        }
    }
    a
}

/// The hardware block functions the CPU reports instructions for, before the self-test.
pub(crate) fn hardware() -> Accel {
    #[cfg(all(any(target_arch = "aarch64", target_arch = "x86_64"), not(pratique_portable)))]
    {
        arch::detect()
    }
    #[cfg(not(all(any(target_arch = "aarch64", target_arch = "x86_64"), not(pratique_portable))))]
    {
        Accel::NONE
    }
}

/// `n` bytes that are not all alike: the self-test's input.
fn pattern(n: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// One block, then 255 more in one call, from two different states: the same as the portable function.
fn agrees256(f: fn(&mut [u32; 8], &[u8])) -> bool {
    let data = pattern(64 * 256);
    for start in [[0u32; 8], [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19]] {
        let (mut hw, mut sw) = (start, start);
        f(&mut hw, &data[..64]);
        sha2::portable_blocks256(&mut sw, &data[..64]);
        f(&mut hw, &data[64..]);
        sha2::portable_blocks256(&mut sw, &data[64..]);
        if hw != sw {
            return false;
        }
    }
    true
}

fn agrees512(f: fn(&mut [u64; 8], &[u8])) -> bool {
    let data = pattern(128 * 128);
    for start in [[0u64; 8], [0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1, 0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179]] {
        let (mut hw, mut sw) = (start, start);
        f(&mut hw, &data[..128]);
        sha2::portable_blocks512(&mut sw, &data[..128]);
        f(&mut hw, &data[128..]);
        sha2::portable_blocks512(&mut sw, &data[128..]);
        if hw != sw {
            return false;
        }
    }
    true
}

#[cfg(all(target_arch = "aarch64", not(pratique_portable)))]
mod arch {
    use super::super::sha2_consts::{K256, K512};
    use super::Accel;
    use core::arch::aarch64::*;

    pub(super) fn detect() -> Accel {
        Accel {
            sha256: std::arch::is_aarch64_feature_detected!("sha2").then_some(sha256 as fn(&mut [u32; 8], &[u8])),
            sha512: std::arch::is_aarch64_feature_detected!("sha3").then_some(sha512 as fn(&mut [u64; 8], &[u8])),
        }
    }

    /// Only ever handed out by `detect`, after the CPU reported the SHA-256 instructions.
    fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: reached only through `detect`, which checked that the CPU has FEAT_SHA256 (and so NEON).
        unsafe { sha256_blocks(state, blocks) }
    }

    /// Only ever handed out by `detect`, after the CPU reported the SHA-512 instructions.
    fn sha512(state: &mut [u64; 8], blocks: &[u8]) {
        // SAFETY: reached only through `detect`, which checked that the CPU has FEAT_SHA512 (Rust's `sha3`).
        unsafe { sha512_blocks(state, blocks) }
    }

    /// SHA-256 over whole 64-byte blocks: four rounds per SHA256H/SHA256H2 pair, the message schedule by SHA256SU0
    /// and SHA256SU1 (the sequence of ARM's own examples and of Linux's sha2-ce).
    #[target_feature(enable = "neon,sha2")]
    unsafe fn sha256_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        let mut abcd = vld1q_u32(state.as_ptr());
        let mut efgh = vld1q_u32(state.as_ptr().add(4));
        for block in blocks.chunks_exact(64) {
            let (abcd0, efgh0) = (abcd, efgh);
            let p = block.as_ptr();
            // the message words are big endian
            let mut m = [
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48)))),
            ];
            // four groups of four rounds at a time, so that every index below is a constant once the inner loop is unrolled
            for g in 0..4 {
                for j in 0..4 {
                    // m[j] holds W[4i..4i+4]; once used, it becomes W[4i+16..4i+20]
                    let wk = vaddq_u32(m[j], vld1q_u32(K256.as_ptr().add(4 * (4 * g + j))));
                    if g < 3 {
                        m[j] = vsha256su1q_u32(vsha256su0q_u32(m[j], m[(j + 1) % 4]), m[(j + 2) % 4], m[(j + 3) % 4]);
                    }
                    let abcd_before = abcd;
                    abcd = vsha256hq_u32(abcd, efgh, wk);
                    efgh = vsha256h2q_u32(efgh, abcd_before, wk);
                }
            }
            abcd = vaddq_u32(abcd, abcd0);
            efgh = vaddq_u32(efgh, efgh0);
        }
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }

    /// SHA-512 over whole 128-byte blocks: two rounds per SHA512H/SHA512H2 pair, the four state registers (ab, cd, ef,
    /// gh) taking turns in the four roles, the message schedule by SHA512SU0 and SHA512SU1 (the sequence of Linux's
    /// sha512-ce).
    #[target_feature(enable = "neon,sha3")]
    unsafe fn sha512_blocks(state: &mut [u64; 8], blocks: &[u8]) {
        let mut st = [vld1q_u64(state.as_ptr()), vld1q_u64(state.as_ptr().add(2)), vld1q_u64(state.as_ptr().add(4)), vld1q_u64(state.as_ptr().add(6))];
        for block in blocks.chunks_exact(128) {
            let saved = st;
            let p = block.as_ptr();
            let mut s = [vdupq_n_u64(0); 8];
            for (i, w) in s.iter_mut().enumerate() {
                *w = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(16 * i))));
            }
            // five groups of eight round pairs, so that every index below is a constant once the inner loop is unrolled
            for g in 0..5 {
                for j in 0..8 {
                    if g > 0 {
                        // W pair r from pairs r - 8, r - 7, r - 4 and r - 3 (the middle two straddled), and r - 1
                        s[j] = vsha512su1q_u64(vsha512su0q_u64(s[j], s[(j + 1) % 8]), s[(j + 7) % 8], vextq_u64::<1>(s[(j + 4) % 8], s[(j + 5) % 8]));
                    }
                    let wk = vaddq_u64(s[j], vld1q_u64(K512.as_ptr().add(2 * (8 * g + j))));
                    // the roles turn by one register every two rounds: (a, b, c, d) = (ab, cd, ef, gh), then (gh, ab, cd, ef), ...
                    let q = j % 4;
                    let (ia, ib, ic, id) = ((4 - q) % 4, (5 - q) % 4, (6 - q) % 4, (7 - q) % 4);
                    let (a, b, c, d) = (st[ia], st[ib], st[ic], st[id]);
                    let sum = vaddq_u64(vextq_u64::<1>(wk, wk), d);
                    let t = vsha512hq_u64(sum, vextq_u64::<1>(c, d), vextq_u64::<1>(b, c));
                    st[id] = vsha512h2q_u64(t, b, a);
                    st[ib] = vaddq_u64(b, t);
                }
            }
            for k in 0..4 {
                st[k] = vaddq_u64(st[k], saved[k]);
            }
        }
        for (k, v) in st.iter().enumerate() {
            vst1q_u64(state.as_mut_ptr().add(2 * k), *v);
        }
    }
}

#[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
mod arch {
    use super::super::sha2_consts::K256;
    use super::Accel;
    use core::arch::x86_64::*;

    pub(super) fn detect() -> Accel {
        let sha = std::is_x86_feature_detected!("sha")
            && std::is_x86_feature_detected!("sse2")
            && std::is_x86_feature_detected!("ssse3")
            && std::is_x86_feature_detected!("sse4.1");
        Accel { sha256: sha.then_some(sha256 as fn(&mut [u32; 8], &[u8])), sha512: None }
    }

    /// Only ever handed out by `detect`, after the CPU reported the SHA extensions.
    fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: reached only through `detect`, which checked SHA, SSE2, SSSE3 and SSE4.1.
        unsafe { sha256_blocks(state, blocks) }
    }

    /// SHA-256 over whole 64-byte blocks with SHA256RNDS2 (two rounds each), SHA256MSG1 and SHA256MSG2, the state kept
    /// as ABEF and CDGH (the arrangement of Intel's own example code).
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn sha256_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
        let tmp = _mm_shuffle_epi32::<0xb1>(_mm_loadu_si128(state.as_ptr() as *const __m128i)); // CDAB
        let s1 = _mm_shuffle_epi32::<0x1b>(_mm_loadu_si128(state.as_ptr().add(4) as *const __m128i)); // EFGH
        let mut abef = _mm_alignr_epi8::<8>(tmp, s1);
        let mut cdgh = _mm_blend_epi16::<0xf0>(s1, tmp);
        for block in blocks.chunks_exact(64) {
            let (abef0, cdgh0) = (abef, cdgh);
            let p = block.as_ptr() as *const __m128i;
            let mut m = [
                _mm_shuffle_epi8(_mm_loadu_si128(p), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(1)), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(2)), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(3)), mask),
            ];
            // four groups of four rounds at a time, so that every index below is a constant once the inner loop is unrolled
            for g in 0..4 {
                for j in 0..4 {
                    let i = 4 * g + j;
                    let wk = _mm_add_epi32(m[j], _mm_loadu_si128(K256.as_ptr().add(4 * i) as *const __m128i));
                    cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                    if (3..15).contains(&i) {
                        // W for the next group of four: m[(j + 1) % 4], which SHA256MSG1 started three groups ago
                        let t = _mm_alignr_epi8::<4>(m[j], m[(j + 3) % 4]);
                        m[(j + 1) % 4] = _mm_sha256msg2_epu32(_mm_add_epi32(m[(j + 1) % 4], t), m[j]);
                    }
                    abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32::<0x0e>(wk));
                    if (1..13).contains(&i) {
                        m[(j + 3) % 4] = _mm_sha256msg1_epu32(m[(j + 3) % 4], m[j]);
                    }
                }
            }
            abef = _mm_add_epi32(abef, abef0);
            cdgh = _mm_add_epi32(cdgh, cdgh0);
        }
        let tmp = _mm_shuffle_epi32::<0x1b>(abef); // FEBA
        let s1 = _mm_shuffle_epi32::<0xb1>(cdgh); // DCHG
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, _mm_blend_epi16::<0xf0>(tmp, s1)); // DCBA
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, _mm_alignr_epi8::<8>(s1, tmp)); // ABEF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha2::{Hash, Sha256, Sha384, Sha512};

    /// The hardware block functions this CPU has give the portable ones' result for every number of blocks to 40 and
    /// from many states, and `detect` keeps them (so the self-test does not throw away working code).
    #[test]
    fn the_hardware_block_functions_agree_with_the_portable_ones() {
        let hw = hardware();
        println!("hardware SHA-256: {}, SHA-512: {}", hw.sha256.is_some(), hw.sha512.is_some());
        let data = pattern(128 * 40);
        let mut rng = crate::fuzz::Rng::new(0x5a2);
        if let Some(f) = hw.sha256 {
            for n in 0..=40 {
                let start: [u32; 8] = std::array::from_fn(|_| rng.next_u64() as u32);
                let (mut a, mut b) = (start, start);
                f(&mut a, &data[..64 * n]);
                sha2::portable_blocks256(&mut b, &data[..64 * n]);
                assert_eq!(a, b, "SHA-256, {n} blocks");
            }
            assert!(detect().sha256.is_some(), "the self-test keeps working SHA-256 code");
        }
        if let Some(f) = hw.sha512 {
            for n in 0..=40 {
                let start: [u64; 8] = std::array::from_fn(|_| rng.next_u64());
                let (mut a, mut b) = (start, start);
                f(&mut a, &data[..128 * n]);
                sha2::portable_blocks512(&mut b, &data[..128 * n]);
                assert_eq!(a, b, "SHA-512, {n} blocks");
            }
            assert!(detect().sha512.is_some(), "the self-test keeps working SHA-512 code");
        }
    }

    /// A block function that is wrong is not used.
    #[test]
    fn a_block_function_that_disagrees_is_refused() {
        fn wrong256(state: &mut [u32; 8], blocks: &[u8]) {
            sha2::portable_blocks256(state, blocks);
            state[3] ^= 1;
        }
        fn wrong512(state: &mut [u64; 8], blocks: &[u8]) {
            sha2::portable_blocks512(state, blocks);
            state[7] = state[7].wrapping_add(1);
        }
        assert!(!agrees256(wrong256));
        assert!(!agrees512(wrong512));
        assert!(agrees256(sha2::portable_blocks256));
        assert!(agrees512(sha2::portable_blocks512));
    }

    /// The CPUs this is built for that have the instructions get them: an M-series Mac or any ARMv8.2 core with SHA-512,
    /// and x86-64 with the SHA extensions. (On a CPU without them there is nothing to check.)
    #[test]
    fn the_hashes_use_the_instructions_where_the_cpu_has_them() {
        let (hw, used) = (hardware(), detect());
        assert_eq!(hw.sha256.is_some(), used.sha256.is_some());
        assert_eq!(hw.sha512.is_some(), used.sha512.is_some());
        // and the public hashes still give the FIPS 180-4 answers through them
        assert_eq!(crate::util::hex(&Sha256::digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(crate::util::hex(&Sha384::digest(b"abc")), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
        assert_eq!(
            crate::util::hex(&Sha512::digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }
}
