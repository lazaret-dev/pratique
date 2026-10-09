//! Hardware AES and carry-less multiplication: AES-NI and PCLMULQDQ on x86-64, the ARMv8
//! Cryptography Extensions (AES and PMULL) on aarch64.
//!
//! The instructions are found at run time (`is_x86_feature_detected!`,
//! `is_aarch64_feature_detected!`), not assumed from the build target, so a generic binary uses
//! them wherever they exist. The first use also runs a self-test (FIPS 197 known answers, plus the
//! CTR and GHASH code against the portable implementations); if anything disagrees the hardware
//! path is switched off for the process and [`super::aes_ct`] is used instead. Both are free of
//! secret-dependent memory accesses and branches.
//!
//! This is the only module in the library with `unsafe` that is not a plain pointer write: the
//! intrinsics are `unsafe fn`s with a CPU feature precondition. Every call site is in this file
//! or reaches it through [`available`], and `Keys` cannot be built unless [`available`] is true.
//!
//! In builds for other CPUs, or with `--cfg pratique_portable`, the same API exists but
//! [`available`] is `false` and nothing here is compiled in.

#[cfg(test)]
thread_local! {
    /// Test builds only: makes this thread's aarch64 one-pass seal read each group of ciphertext back from memory to hash
    /// it, as it did from B-85 until the timing tests showed (under macOS on an Apple M5) that its time then depended a
    /// little on the plaintext; `crypto::timing::aes_gcm_one_pass_against_two_passes` compares the two. No effect on
    /// other CPUs.
    pub(crate) static SEAL_BY_RELOAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), not(pratique_portable)))]
mod real {
    use super::super::aes::{Aes, Backend};
    use super::super::{aes_ct, ghash};
    use crate::zeroize::Zeroize;
    use std::sync::OnceLock;

    #[cfg(target_arch = "x86_64")]
    mod arch {
        use core::arch::x86_64::*;

        pub(super) fn cpu_supports() -> bool {
            std::is_x86_feature_detected!("aes")
                && std::is_x86_feature_detected!("pclmulqdq")
                && std::is_x86_feature_detected!("sse2")
                && std::is_x86_feature_detected!("ssse3")
        }

        #[inline(always)]
        fn lanes(nonce: &[u8; 12]) -> [i32; 3] {
            [
                i32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
                i32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
                i32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
            ]
        }

        #[target_feature(enable = "aes,sse2")]
        unsafe fn load_keys(rk: &[[u8; 16]; 15], nr: usize) -> [__m128i; 15] {
            let mut out = [_mm_setzero_si128(); 15];
            for r in 0..=nr {
                out[r] = _mm_loadu_si128(rk[r].as_ptr() as *const __m128i);
            }
            out
        }

        #[target_feature(enable = "aes,sse2")]
        unsafe fn encrypt_one(rks: &[__m128i; 15], nr: usize, block: __m128i) -> __m128i {
            let mut s = _mm_xor_si128(block, rks[0]);
            for r in 1..nr {
                s = _mm_aesenc_si128(s, rks[r]);
            }
            _mm_aesenclast_si128(s, rks[nr])
        }

        /// # Safety
        /// The CPU must support AES-NI.
        #[target_feature(enable = "aes,sse2")]
        pub(super) unsafe fn encrypt_block(rk: &[[u8; 16]; 15], nr: usize, block: &[u8; 16]) -> [u8; 16] {
            let rks = load_keys(rk, nr);
            let ct = encrypt_one(&rks, nr, _mm_loadu_si128(block.as_ptr() as *const __m128i));
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, ct);
            out
        }

        /// CTR keystream XOR, eight blocks in flight.
        ///
        /// # Safety
        /// The CPU must support AES-NI.
        #[target_feature(enable = "aes,sse2")]
        pub(super) unsafe fn ctr_xor(rk: &[[u8; 16]; 15], nr: usize, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, nr);
            let n = lanes(nonce);
            let mut ctr = counter;
            let mut chunks = data.chunks_exact_mut(128);
            for chunk in &mut chunks {
                let mut s = [_mm_setzero_si128(); 8];
                for i in 0..8 {
                    let c = ctr.wrapping_add(i as u32);
                    // the counter is big endian in the last four bytes of the block
                    s[i] = _mm_xor_si128(_mm_set_epi32(c.swap_bytes() as i32, n[2], n[1], n[0]), rks[0]);
                }
                for r in 1..nr {
                    for i in 0..8 {
                        s[i] = _mm_aesenc_si128(s[i], rks[r]);
                    }
                }
                for i in 0..8 {
                    let ks = _mm_aesenclast_si128(s[i], rks[nr]);
                    let p = chunk.as_mut_ptr().add(16 * i) as *mut __m128i;
                    _mm_storeu_si128(p, _mm_xor_si128(_mm_loadu_si128(p), ks));
                }
                ctr = ctr.wrapping_add(8);
            }
            for chunk in chunks.into_remainder().chunks_mut(16) {
                let ks = encrypt_one(&rks, nr, _mm_set_epi32(ctr.swap_bytes() as i32, n[2], n[1], n[0]));
                let mut buf = [0u8; 16];
                _mm_storeu_si128(buf.as_mut_ptr() as *mut __m128i, ks);
                for (d, k) in chunk.iter_mut().zip(buf.iter()) {
                    *d ^= k;
                }
                buf.zeroize();
                ctr = ctr.wrapping_add(1);
            }
        }

        // ------------------------------------------------------------------------------------------ GCM in one pass
        //
        // AES-GCM as AES-NI and PCLMULQDQ do it best: the keystream of eight blocks in flight, and the hash of the
        // data eight blocks at a time with the products of all eight summed before the one reduction (the blocks
        // are multiplied by H^8, H^7, ... H, so that the sum is what eight single steps would have made). The
        // hash of one group of blocks is independent of the keystream of the next, so the processor does both
        // together. Blocks are kept byte-reversed (the form in which the 128-bit integer is the polynomial with
        // x^0 at the top bit, which is what the carry-less product wants; see `reduce`).

        /// The block with its bytes in the other order.
        #[inline]
        #[target_feature(enable = "ssse3,sse2")]
        unsafe fn bswap(x: __m128i) -> __m128i {
            _mm_shuffle_epi8(x, _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
        }

        /// Eight blocks at `p`, byte-reversed.
        #[inline]
        #[target_feature(enable = "ssse3,sse2")]
        unsafe fn load8_be(p: *const u8) -> [__m128i; 8] {
            let mut x = [_mm_setzero_si128(); 8];
            for i in 0..8 {
                x[i] = bswap(_mm_loadu_si128(p.add(16 * i) as *const __m128i));
            }
            x
        }

        /// The three sums of 64 x 64 bit carry-less products that products of 128-bit values are made of: the low
        /// halves, the high halves, and the two cross terms together.
        #[derive(Clone, Copy)]
        struct Sums {
            lo: __m128i,
            mid: __m128i,
            hi: __m128i,
        }

        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2")]
        unsafe fn no_sums() -> Sums {
            let z = _mm_setzero_si128();
            Sums { lo: z, mid: z, hi: z }
        }

        /// Adds the product of `a` and `h` (unreduced) to the sums.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2")]
        unsafe fn mac(s: &mut Sums, a: __m128i, h: __m128i) {
            s.lo = _mm_xor_si128(s.lo, _mm_clmulepi64_si128::<0x00>(a, h));
            s.hi = _mm_xor_si128(s.hi, _mm_clmulepi64_si128::<0x11>(a, h));
            s.mid = _mm_xor_si128(s.mid, _mm_xor_si128(_mm_clmulepi64_si128::<0x10>(a, h), _mm_clmulepi64_si128::<0x01>(a, h)));
        }

        /// The 256-bit sum of products, reduced modulo x^128 + x^7 + x^2 + x + 1 (B-104).
        ///
        /// With the blocks byte-reversed, bit j of the integer is the coefficient of x^(127 - j), so the product of two
        /// of them has bit m for x^(254 - m): one place off the 256-bit layout (bit m for x^(255 - m)) that would put the
        /// high half's bit j at x^(127 - j) again. The powers of H are stored "twisted", times x^-1 (`powers`), which
        /// makes up for it: the products of blocks by them are laid out as 256 bits, with no shift. The low half (the
        /// terms from x^128 up) is then folded back 64 bits at a time, each fold one carry-less product by the
        /// constant 0xc2 << 56 (x^128 = x^7 + x^2 + x + 1, in this layout the 129-bit 2^128 + C with C = 2^127 + 2^126 +
        /// 2^121) and a swap of halves: two products, two shuffles and three additions, where the shifts and masks of
        /// Gueron and Kounavis' reduction (the one before) took about twenty instructions, several of them on the
        /// execution port that the AES rounds need. A tenth more AES-GCM throughput on an x86-64 server.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2")]
        unsafe fn fold(s: Sums) -> __m128i {
            let lo = _mm_xor_si128(s.lo, _mm_slli_si128::<8>(s.mid));
            let hi = _mm_xor_si128(s.hi, _mm_srli_si128::<8>(s.mid));
            let c = _mm_set_epi64x(0xc200_0000_0000_0000u64 as i64, 0);
            // the lowest 64 bits (x^192 to x^255) folded: into the next 64 and the high half
            let t = _mm_clmulepi64_si128::<0x10>(lo, c);
            let y = _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(lo), t);
            // then the next 64 (x^128 to x^191), which is now y's low half
            let t2 = _mm_clmulepi64_si128::<0x10>(y, c);
            _mm_xor_si128(hi, _mm_xor_si128(_mm_shuffle_epi32::<0x4e>(y), t2))
        }

        /// The product of a block and a twisted power of H (both byte-reversed), reduced: the product of the block and
        /// the power itself.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2")]
        unsafe fn gfmul(a: __m128i, b: __m128i) -> __m128i {
            let mut s = no_sums();
            mac(&mut s, a, b);
            fold(s)
        }

        /// h x^-1, for a byte-reversed h: a shift left by one, and x^-1 = x^127 + x^6 + x + 1 added if the coefficient
        /// of x^0 (the top bit) went out. With a mask, as H is secret.
        fn twist(h: u128) -> u128 {
            (h << 1) ^ (0u128.wrapping_sub(h >> 127) & 0xc200_0000_0000_0000_0000_0000_0000_0001)
        }

        /// H^1 ... H^8 for the hash subkey block `h` (the encryption of the zero block, as the cipher gave it), twisted
        /// (times x^-1, see [`fold`]), in the form [`ghash8`] uses.
        ///
        /// # Safety
        /// The CPU must support AES-NI's companions: PCLMULQDQ, SSSE3 and SSE2.
        #[target_feature(enable = "pclmulqdq,sse2,ssse3")]
        pub(super) unsafe fn powers(h: &[u8; 16]) -> [u128; 8] {
            let h1 = bswap(_mm_loadu_si128(h.as_ptr() as *const __m128i));
            let mut x = 0u128;
            _mm_storeu_si128(&mut x as *mut u128 as *mut __m128i, h1);
            let ht = twist(x);
            let ht = _mm_loadu_si128(&ht as *const u128 as *const __m128i);
            // H^i = H^(i-1) times H, by the twisted H
            let mut p = [h1; 8];
            for i in 1..8 {
                p[i] = gfmul(p[i - 1], ht);
            }
            let mut out = [0u128; 8];
            for i in 0..8 {
                _mm_storeu_si128(out.as_mut_ptr().add(i) as *mut __m128i, p[i]);
                out[i] = twist(out[i]);
            }
            out
        }

        #[inline]
        #[target_feature(enable = "sse2")]
        unsafe fn load_powers(pow: &[u128; 8]) -> [__m128i; 8] {
            let mut h = [_mm_setzero_si128(); 8];
            for i in 0..8 {
                h[i] = _mm_loadu_si128(pow.as_ptr().add(i) as *const __m128i);
            }
            h
        }

        /// `acc` with eight blocks (byte-reversed) absorbed: ((acc ^ x0) H^8 ^ x1 H^7 ^ ... ^ x7 H).
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2")]
        unsafe fn ghash8(acc: __m128i, x: &[__m128i; 8], h: &[__m128i; 8]) -> __m128i {
            let mut s = no_sums();
            mac(&mut s, _mm_xor_si128(x[0], acc), h[7]);
            for j in 1..8 {
                mac(&mut s, x[j], h[7 - j]);
            }
            fold(s)
        }

        /// `acc` with the first `n` (1 to 8) of the blocks absorbed.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2")]
        unsafe fn ghash_n(acc: __m128i, x: &[__m128i; 8], n: usize, h: &[__m128i; 8]) -> __m128i {
            let mut s = no_sums();
            mac(&mut s, _mm_xor_si128(x[0], acc), h[n - 1]);
            for j in 1..n {
                mac(&mut s, x[j], h[n - 1 - j]);
            }
            fold(s)
        }

        /// `acc` with `data` absorbed, a last partial block zero-padded.
        #[target_feature(enable = "pclmulqdq,sse2,ssse3")]
        unsafe fn absorb(mut acc: __m128i, data: &[u8], h: &[__m128i; 8]) -> __m128i {
            let mut chunks = data.chunks_exact(128);
            for c in &mut chunks {
                acc = ghash8(acc, &load8_be(c.as_ptr()), h);
            }
            let rest = chunks.remainder();
            if !rest.is_empty() {
                let mut buf = [0u8; 128];
                buf[..rest.len()].copy_from_slice(rest);
                acc = ghash_n(acc, &load8_be(buf.as_ptr()), rest.len().div_ceil(16), h);
            }
            acc
        }

        /// The GHASH value S for `acc` after the lengths block: the hash is done.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse2,ssse3")]
        unsafe fn finish(acc: __m128i, aad_len: usize, data_len: usize, h: &[__m128i; 8], ej0: __m128i) -> [u8; 16] {
            // the block is the two bit counts, big-endian, A first; byte-reversed that is C in the low half
            let lens = _mm_set_epi64x((aad_len as u64 * 8) as i64, (data_len as u64 * 8) as i64);
            let s = bswap(gfmul(_mm_xor_si128(acc, lens), h[0]));
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, _mm_xor_si128(s, ej0));
            out
        }

        /// E(J0), the block that masks the tag: the nonce and the counter 1. Made at the start of a seal or an open, so
        /// that it is ready by the end instead of being a separate call after it (B-103).
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        unsafe fn tag_mask<const NR: usize>(rks: &[__m128i; 15], n: &[i32; 3]) -> __m128i {
            encrypt_one(rks, NR, _mm_set_epi32(1u32.swap_bytes() as i32, n[2], n[1], n[0]))
        }

        /// The counter blocks `ctr` to `ctr + 7` with the first round key added: the start of [`keystream8`].
        #[inline]
        #[target_feature(enable = "sse2")]
        unsafe fn counter_blocks(rk0: __m128i, n: &[i32; 3], ctr: u32) -> [__m128i; 8] {
            let mut s = [_mm_setzero_si128(); 8];
            // the counter is big endian in the last four bytes of the block, so the lane holds it byte-reversed, its low
            // byte at the top: while that byte does not overflow, counter + i is the lane + (i << 24), one addition where
            // building each block took four instructions, two of them on the port the carry-less products need (B-103).
            // Which way depends only on the counter, which is public.
            let first = _mm_set_epi32(ctr.swap_bytes() as i32, n[2], n[1], n[0]);
            if ctr & 0xff <= 0xff - 7 {
                for (i, v) in s.iter_mut().enumerate() {
                    *v = _mm_xor_si128(_mm_add_epi32(first, _mm_set_epi32((i as i32) << 24, 0, 0, 0)), rk0);
                }
            } else {
                for (i, v) in s.iter_mut().enumerate() {
                    let c = ctr.wrapping_add(i as u32);
                    *v = _mm_xor_si128(_mm_set_epi32(c.swap_bytes() as i32, n[2], n[1], n[0]), rk0);
                }
            }
            s
        }

        /// The keystream of eight blocks, counters `ctr` to `ctr + 7`.
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        unsafe fn keystream8<const NR: usize>(rks: &[__m128i; 15], n: &[i32; 3], ctr: u32) -> [__m128i; 8] {
            let mut s = counter_blocks(rks[0], n, ctr);
            for r in 1..NR {
                for i in 0..8 {
                    s[i] = _mm_aesenc_si128(s[i], rks[r]);
                }
            }
            for i in 0..8 {
                s[i] = _mm_aesenclast_si128(s[i], rks[NR]);
            }
            s
        }

        /// The keystream of eight blocks (as [`keystream8`]) and `acc` with eight other blocks absorbed (as [`ghash8`]): one
        /// block's products after each of the first eight rounds, so that the processor does the two at once (B-103: 16 KiB
        /// sealed in 4.1 us on an x86-64 server where the keystream alone takes 3.1 and the hash alone 2.1, and had taken
        /// 5.4 when the two were made one after the other).
        #[inline]
        #[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]
        unsafe fn keystream8_hash8<const NR: usize>(rks: &[__m128i; 15], n: &[i32; 3], ctr: u32, acc: __m128i, x: &[__m128i; 8], h: &[__m128i; 8]) -> ([__m128i; 8], __m128i) {
            let mut s = counter_blocks(rks[0], n, ctr);
            let mut sums = no_sums();
            for r in 1..NR {
                for v in s.iter_mut() {
                    *v = _mm_aesenc_si128(*v, rks[r]);
                }
                if r <= 8 {
                    let j = r - 1;
                    let a = if j == 0 { _mm_xor_si128(x[0], acc) } else { x[j] };
                    mac(&mut sums, a, h[7 - j]);
                }
                // The end of a round, for the compiler: an empty asm that takes the eight blocks and the three sums in and
                // gives them back, so that each round's encryptions and products are made between it and the one before.
                // Without it the compiler puts all eighty encryptions before all the products, and the processor, its
                // queue full of encryptions waiting on each other, does the two one after the other. (An opaque use of
                // the sums alone, `black_box`, got half of the way.)
                // SAFETY: the template is a comment: no instruction, no memory, the registers given back as they came.
                core::arch::asm!(
                    "/* {0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} */",
                    inout(xmm_reg) s[0], inout(xmm_reg) s[1], inout(xmm_reg) s[2], inout(xmm_reg) s[3],
                    inout(xmm_reg) s[4], inout(xmm_reg) s[5], inout(xmm_reg) s[6], inout(xmm_reg) s[7],
                    inout(xmm_reg) sums.lo, inout(xmm_reg) sums.mid, inout(xmm_reg) sums.hi,
                    options(nomem, nostack, preserves_flags),
                );
            }
            for v in s.iter_mut() {
                *v = _mm_aesenclast_si128(*v, rks[NR]);
            }
            (s, fold(sums))
        }

        /// Encrypts `data` in place (counters from 2) and returns the tag: the GHASH value S of `aad` and the ciphertext,
        /// masked with E(J0).
        #[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]
        unsafe fn seal_impl<const NR: usize>(rk: &[[u8; 16]; 15], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, NR);
            let n = lanes(nonce);
            let ej0 = tag_mask::<NR>(&rks, &n);
            let h = load_powers(pow);
            let mut acc = absorb(_mm_setzero_si128(), aad, &h);
            let total = data.len();
            let base = data.as_mut_ptr();
            let mut ctr = 2u32;
            let mut off = 0usize;
            // the group encrypted last time round, whose ciphertext is hashed while this one is being encrypted
            let mut prev: Option<usize> = None;
            while total - off >= 128 {
                let p = base.add(off);
                let ks = match prev {
                    Some(o) => {
                        let (ks, a) = keystream8_hash8::<NR>(&rks, &n, ctr, acc, &load8_be(base.add(o)), &h);
                        acc = a;
                        ks
                    }
                    None => keystream8::<NR>(&rks, &n, ctr),
                };
                for i in 0..8 {
                    let q = p.add(16 * i) as *mut __m128i;
                    _mm_storeu_si128(q, _mm_xor_si128(_mm_loadu_si128(q), ks[i]));
                }
                prev = Some(off);
                off += 128;
                ctr = ctr.wrapping_add(8);
            }
            if let Some(o) = prev {
                acc = ghash8(acc, &load8_be(base.add(o)), &h);
            }
            let rem = total - off;
            if rem > 0 {
                // the last whole blocks in place, from registers, and a last partial block through 16 bytes on the stack
                // (B-103: a 128-byte buffer copied in and out and wiped byte by byte was about a third of a 100-byte seal)
                let ks = keystream8::<NR>(&rks, &n, ctr);
                let (full, part) = (rem / 16, rem % 16);
                let mut x = [_mm_setzero_si128(); 8];
                let p = base.add(off);
                for i in 0..full {
                    let q = p.add(16 * i) as *mut __m128i;
                    let c = _mm_xor_si128(_mm_loadu_si128(q), ks[i]);
                    _mm_storeu_si128(q, c);
                    x[i] = bswap(c);
                }
                if part > 0 {
                    let tail = &mut data[off + 16 * full..];
                    let mut b = [0u8; 16];
                    b[..part].copy_from_slice(tail);
                    let q = b.as_mut_ptr() as *mut __m128i;
                    _mm_storeu_si128(q, _mm_xor_si128(_mm_loadu_si128(q), ks[full]));
                    tail.copy_from_slice(&b[..part]);
                    // what is hashed is the ciphertext and zeros: the keystream over the padding is dropped
                    b[part..].fill(0);
                    x[full] = bswap(_mm_loadu_si128(q));
                    b.zeroize();
                }
                acc = ghash_n(acc, &x, rem.div_ceil(16), &h);
            }
            finish(acc, aad.len(), total, &h, ej0)
        }

        /// Decrypts `data` in place (counters from 2) and returns the tag the ciphertext it was should have: the GHASH
        /// value S of `aad` and that ciphertext, masked with E(J0). (The caller checks the tag, and puts the ciphertext back
        /// if it is wrong.)
        #[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]
        unsafe fn open_impl<const NR: usize>(rk: &[[u8; 16]; 15], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, NR);
            let n = lanes(nonce);
            let ej0 = tag_mask::<NR>(&rks, &n);
            let h = load_powers(pow);
            let mut acc = absorb(_mm_setzero_si128(), aad, &h);
            let total = data.len();
            let base = data.as_mut_ptr();
            let mut ctr = 2u32;
            let mut off = 0usize;
            while total - off >= 128 {
                let p = base.add(off);
                let mut c = [_mm_setzero_si128(); 8];
                for i in 0..8 {
                    c[i] = _mm_loadu_si128(p.add(16 * i) as *const __m128i);
                }
                // the hash of the ciphertext and the keystream do not depend on each other: made together
                let mut x = c;
                for v in x.iter_mut() {
                    *v = bswap(*v);
                }
                let (ks, a) = keystream8_hash8::<NR>(&rks, &n, ctr, acc, &x, &h);
                acc = a;
                for i in 0..8 {
                    _mm_storeu_si128(p.add(16 * i) as *mut __m128i, _mm_xor_si128(c[i], ks[i]));
                }
                off += 128;
                ctr = ctr.wrapping_add(8);
            }
            let rem = total - off;
            if rem > 0 {
                // as in `seal_impl`: whole blocks in place, a partial one through 16 bytes on the stack
                let (full, part) = (rem / 16, rem % 16);
                let p = base.add(off);
                let mut c = [_mm_setzero_si128(); 8];
                for (i, v) in c.iter_mut().enumerate().take(full) {
                    *v = _mm_loadu_si128(p.add(16 * i) as *const __m128i);
                }
                let mut b = [0u8; 16];
                if part > 0 {
                    b[..part].copy_from_slice(&data[off + 16 * full..]);
                    c[full] = _mm_loadu_si128(b.as_ptr() as *const __m128i);
                }
                let mut x = c;
                for v in x.iter_mut() {
                    *v = bswap(*v);
                }
                acc = ghash_n(acc, &x, rem.div_ceil(16), &h);
                let ks = keystream8::<NR>(&rks, &n, ctr);
                for i in 0..full {
                    _mm_storeu_si128(p.add(16 * i) as *mut __m128i, _mm_xor_si128(c[i], ks[i]));
                }
                if part > 0 {
                    let q = b.as_mut_ptr() as *mut __m128i;
                    _mm_storeu_si128(q, _mm_xor_si128(c[full], ks[full]));
                    data[off + 16 * full..].copy_from_slice(&b[..part]);
                    b.zeroize();
                }
            }
            finish(acc, aad.len(), total, &h, ej0)
        }

        /// # Safety
        /// The CPU must support AES-NI, PCLMULQDQ, SSSE3 and SSE2. `nr` is 10 or 14.
        pub(super) unsafe fn gcm_seal(rk: &[[u8; 16]; 15], nr: usize, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            match nr {
                10 => seal_impl::<10>(rk, nonce, aad, data, pow),
                14 => seal_impl::<14>(rk, nonce, aad, data, pow),
                _ => unreachable!("AES keys have 10 or 14 rounds"),
            }
        }

        /// # Safety
        /// As for [`gcm_seal`].
        pub(super) unsafe fn gcm_open(rk: &[[u8; 16]; 15], nr: usize, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            match nr {
                10 => open_impl::<10>(rk, nonce, aad, data, pow),
                14 => open_impl::<14>(rk, nonce, aad, data, pow),
                _ => unreachable!("AES keys have 10 or 14 rounds"),
            }
        }

        /// 64 x 64 -> 128 bit carry-less product.
        ///
        /// # Safety
        /// The CPU must support PCLMULQDQ.
        #[target_feature(enable = "pclmulqdq,sse2")]
        #[inline]
        pub(crate) unsafe fn clmul64(a: u64, b: u64) -> u128 {
            let r = _mm_clmulepi64_si128::<0x00>(_mm_cvtsi64_si128(a as i64), _mm_cvtsi64_si128(b as i64));
            let lo = _mm_cvtsi128_si64(r) as u64;
            let hi = _mm_cvtsi128_si64(_mm_unpackhi_epi64(r, r)) as u64;
            ((hi as u128) << 64) | lo as u128
        }

        /// # Safety
        /// The CPU must support PCLMULQDQ.
        #[target_feature(enable = "pclmulqdq,sse2")]
        pub(super) unsafe fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
            crate::crypto::ghash::hash_with::<true>(h, aad, ct)
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod arch {
        use core::arch::aarch64::*;

        pub(super) fn cpu_supports() -> bool {
            std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull")
        }

        #[target_feature(enable = "neon,aes")]
        unsafe fn load_keys(rk: &[[u8; 16]; 15], nr: usize) -> [uint8x16_t; 15] {
            let mut out = [vdupq_n_u8(0); 15];
            for r in 0..=nr {
                out[r] = vld1q_u8(rk[r].as_ptr());
            }
            out
        }

        #[target_feature(enable = "neon,aes")]
        unsafe fn counter_block(nonce: &[u8; 12], ctr: u32) -> uint8x16_t {
            let mut b = [0u8; 16];
            b[..12].copy_from_slice(nonce);
            b[12..].copy_from_slice(&ctr.to_be_bytes());
            vld1q_u8(b.as_ptr())
        }

        #[target_feature(enable = "neon,aes")]
        unsafe fn encrypt_one(rks: &[uint8x16_t; 15], nr: usize, block: uint8x16_t) -> uint8x16_t {
            let mut s = block;
            // AESE xors in the round key, then SubBytes and ShiftRows; AESMC is MixColumns
            for r in 0..nr - 1 {
                s = vaesmcq_u8(vaeseq_u8(s, rks[r]));
            }
            s = vaeseq_u8(s, rks[nr - 1]);
            veorq_u8(s, rks[nr])
        }

        /// # Safety
        /// The CPU must support the ARMv8 AES instructions.
        #[target_feature(enable = "neon,aes")]
        pub(super) unsafe fn encrypt_block(rk: &[[u8; 16]; 15], nr: usize, block: &[u8; 16]) -> [u8; 16] {
            let rks = load_keys(rk, nr);
            let ct = encrypt_one(&rks, nr, vld1q_u8(block.as_ptr()));
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), ct);
            out
        }

        /// CTR keystream XOR, eight blocks in flight.
        ///
        /// # Safety
        /// The CPU must support the ARMv8 AES instructions.
        #[target_feature(enable = "neon,aes")]
        pub(super) unsafe fn ctr_xor(rk: &[[u8; 16]; 15], nr: usize, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, nr);
            let mut ctr = counter;
            let mut chunks = data.chunks_exact_mut(128);
            for chunk in &mut chunks {
                let mut s = [vdupq_n_u8(0); 8];
                for i in 0..8 {
                    s[i] = counter_block(nonce, ctr.wrapping_add(i as u32));
                }
                for r in 0..nr - 1 {
                    for i in 0..8 {
                        s[i] = vaesmcq_u8(vaeseq_u8(s[i], rks[r]));
                    }
                }
                for i in 0..8 {
                    let ks = veorq_u8(vaeseq_u8(s[i], rks[nr - 1]), rks[nr]);
                    let p = chunk.as_mut_ptr().add(16 * i);
                    vst1q_u8(p, veorq_u8(vld1q_u8(p), ks));
                }
                ctr = ctr.wrapping_add(8);
            }
            for chunk in chunks.into_remainder().chunks_mut(16) {
                let ks = encrypt_one(&rks, nr, counter_block(nonce, ctr));
                let mut buf = [0u8; 16];
                vst1q_u8(buf.as_mut_ptr(), ks);
                for (d, k) in chunk.iter_mut().zip(buf.iter()) {
                    *d ^= k;
                }
                buf.zeroize();
                ctr = ctr.wrapping_add(1);
            }
        }

        // ------------------------------------------------------------------------------------------ GCM in one pass
        //
        // As on x86-64 (see there): the keystream of eight blocks in flight, and the hash of eight blocks with the
        // products of all eight summed before one reduction, the hash of one group done while the next is encrypted.
        // The blocks are kept with the bits of each byte reversed (RBIT), the form in which the 128-bit little-endian
        // integer is the polynomial with x^i at bit i (the order of `ghash::hash_with`'s reflected key): PMULL then
        // multiplies the polynomials as they are, and the reduction modulo x^128 + x^7 + x^2 + x + 1 folds the top half
        // down with two products by 0x87 (x^7 + x^2 + x + 1) and no shifts.

        /// The polynomial of a GCM block, or the block of a polynomial (the bits of each byte reversed).
        #[inline]
        #[target_feature(enable = "neon")]
        unsafe fn rbit(x: uint8x16_t) -> uint8x16_t {
            vrbitq_u8(x)
        }

        /// Eight blocks at `p`, as polynomials.
        #[inline]
        #[target_feature(enable = "neon")]
        unsafe fn load8_poly(p: *const u8) -> [uint8x16_t; 8] {
            let mut x = [vdupq_n_u8(0); 8];
            for (i, v) in x.iter_mut().enumerate() {
                *v = rbit(vld1q_u8(p.add(16 * i)));
            }
            x
        }

        /// The three sums of 64 x 64 bit carry-less products that products of 128-bit values are made of: the low
        /// halves, the high halves, and the two cross terms together.
        #[derive(Clone, Copy)]
        struct Sums {
            lo: uint8x16_t,
            mid: uint8x16_t,
            hi: uint8x16_t,
        }

        #[inline]
        #[target_feature(enable = "neon")]
        unsafe fn no_sums() -> Sums {
            let z = vdupq_n_u8(0);
            Sums { lo: z, mid: z, hi: z }
        }

        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn pmull(a: u64, b: u64) -> uint8x16_t {
            vreinterpretq_u8_p128(vmull_p64(a, b))
        }

        /// Adds the product of `a` and `h` (unreduced) to the sums.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn mac(s: &mut Sums, a: uint8x16_t, h: uint8x16_t) {
            let (a, h) = (vreinterpretq_u64_u8(a), vreinterpretq_u64_u8(h));
            let (a0, a1, h0, h1) = (vgetq_lane_u64::<0>(a), vgetq_lane_u64::<1>(a), vgetq_lane_u64::<0>(h), vgetq_lane_u64::<1>(h));
            s.lo = veorq_u8(s.lo, pmull(a0, h0));
            s.hi = veorq_u8(s.hi, pmull(a1, h1));
            s.mid = veorq_u8(s.mid, veorq_u8(pmull(a0, h1), pmull(a1, h0)));
        }

        /// The 255-bit sum of products reduced modulo x^128 + x^7 + x^2 + x + 1. With the product as the limbs P0 to P3
        /// (x^0, x^64, x^128, x^192): P3 x^192 = P3 x^64 (x^7 + x^2 + x + 1), at most 71 bits at x^64, which goes into P1
        /// and P2; then P2 x^128 = P2 (x^7 + x^2 + x + 1), at most 71 bits at x^0, into P0 and P1.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn fold(s: Sums) -> uint8x16_t {
            let z = vdupq_n_u8(0);
            // the cross terms are at x^64: their low half into P1, their high half into P2
            let lo = veorq_u8(s.lo, vextq_u8::<8>(z, s.mid));
            let hi = veorq_u8(s.hi, vextq_u8::<8>(s.mid, z));
            let hi64 = vreinterpretq_u64_u8(hi);
            let r = pmull(vgetq_lane_u64::<1>(hi64), 0x87);
            let r64 = vreinterpretq_u64_u8(r);
            let p2 = vgetq_lane_u64::<0>(hi64) ^ vgetq_lane_u64::<1>(r64);
            let lo = veorq_u8(lo, vextq_u8::<8>(z, r));
            veorq_u8(lo, pmull(p2, 0x87))
        }

        /// The product of two polynomials, reduced.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn gfmul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
            let mut s = no_sums();
            mac(&mut s, a, b);
            fold(s)
        }

        /// H^1 ... H^8 for the hash subkey block `h` (the encryption of the zero block, as the cipher gave it), as
        /// polynomials.
        ///
        /// # Safety
        /// The CPU must support PMULL (the `aes` feature).
        #[target_feature(enable = "neon,aes")]
        pub(super) unsafe fn powers(h: &[u8; 16]) -> [u128; 8] {
            let h1 = rbit(vld1q_u8(h.as_ptr()));
            let mut p = [h1; 8];
            for i in 1..8 {
                p[i] = gfmul(p[i - 1], h1);
            }
            let mut out = [0u128; 8];
            for i in 0..8 {
                vst1q_u8(out.as_mut_ptr().add(i) as *mut u8, p[i]);
            }
            out
        }

        #[inline]
        #[target_feature(enable = "neon")]
        unsafe fn load_powers(pow: &[u128; 8]) -> [uint8x16_t; 8] {
            let mut h = [vdupq_n_u8(0); 8];
            for (i, v) in h.iter_mut().enumerate() {
                *v = vld1q_u8(pow.as_ptr().add(i) as *const u8);
            }
            h
        }

        /// `acc` with eight blocks (polynomials) absorbed: ((acc ^ x0) H^8 ^ x1 H^7 ^ ... ^ x7 H).
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn ghash8(acc: uint8x16_t, x: &[uint8x16_t; 8], h: &[uint8x16_t; 8]) -> uint8x16_t {
            let mut s = no_sums();
            mac(&mut s, veorq_u8(x[0], acc), h[7]);
            for j in 1..8 {
                mac(&mut s, x[j], h[7 - j]);
            }
            fold(s)
        }

        /// `acc` with the first `n` (1 to 8) of the blocks absorbed.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn ghash_n(acc: uint8x16_t, x: &[uint8x16_t; 8], n: usize, h: &[uint8x16_t; 8]) -> uint8x16_t {
            let mut s = no_sums();
            mac(&mut s, veorq_u8(x[0], acc), h[n - 1]);
            for j in 1..n {
                mac(&mut s, x[j], h[n - 1 - j]);
            }
            fold(s)
        }

        /// `acc` with `data` absorbed, a last partial block zero-padded.
        #[target_feature(enable = "neon,aes")]
        unsafe fn absorb(mut acc: uint8x16_t, data: &[u8], h: &[uint8x16_t; 8]) -> uint8x16_t {
            let mut chunks = data.chunks_exact(128);
            for c in &mut chunks {
                acc = ghash8(acc, &load8_poly(c.as_ptr()), h);
            }
            let rest = chunks.remainder();
            if !rest.is_empty() {
                let mut buf = [0u8; 128];
                buf[..rest.len()].copy_from_slice(rest);
                acc = ghash_n(acc, &load8_poly(buf.as_ptr()), rest.len().div_ceil(16), h);
            }
            acc
        }

        /// The GHASH value S for `acc` after the lengths block: the hash is done.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn finish(acc: uint8x16_t, aad_len: usize, data_len: usize, h: &[uint8x16_t; 8], ej0: uint8x16_t) -> [u8; 16] {
            // the block is the two bit counts, big-endian, A first
            let mut lens = [0u8; 16];
            lens[..8].copy_from_slice(&(aad_len as u64 * 8).to_be_bytes());
            lens[8..].copy_from_slice(&(data_len as u64 * 8).to_be_bytes());
            let s = rbit(gfmul(veorq_u8(acc, rbit(vld1q_u8(lens.as_ptr()))), h[0]));
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), veorq_u8(s, ej0));
            out
        }

        /// E(J0), the block that masks the tag: the nonce and the counter 1. Made at the start of a seal or an open, so
        /// that it is ready by the end instead of being a separate call after it (B-103).
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn tag_mask<const NR: usize>(rks: &[uint8x16_t; 15], base: uint32x4_t) -> uint8x16_t {
            encrypt_one(rks, NR, vreinterpretq_u8_u32(vsetq_lane_u32::<3>(1u32.swap_bytes(), base)))
        }

        /// The keystream of eight blocks, counters `ctr` to `ctr + 7` after the nonce in `base`.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        unsafe fn keystream8<const NR: usize>(rks: &[uint8x16_t; 15], base: uint32x4_t, ctr: u32) -> [uint8x16_t; 8] {
            let mut s = [vdupq_n_u8(0); 8];
            for (i, v) in s.iter_mut().enumerate() {
                // the counter is big endian in the last four bytes of the block
                *v = vreinterpretq_u8_u32(vsetq_lane_u32::<3>(ctr.wrapping_add(i as u32).swap_bytes(), base));
            }
            for r in 0..NR - 1 {
                for v in s.iter_mut() {
                    *v = vaesmcq_u8(vaeseq_u8(*v, rks[r]));
                }
            }
            for v in s.iter_mut() {
                *v = veorq_u8(vaeseq_u8(*v, rks[NR - 1]), rks[NR]);
            }
            s
        }

        #[inline]
        #[target_feature(enable = "neon")]
        unsafe fn nonce_base(nonce: &[u8; 12]) -> uint32x4_t {
            let mut b = [0u8; 16];
            b[..12].copy_from_slice(nonce);
            vreinterpretq_u32_u8(vld1q_u8(b.as_ptr()))
        }

        /// Encrypts `data` in place (counters from 2) and returns the tag (S masked with E(J0), as on x86-64). Each group of
        /// eight blocks is hashed from the registers its ciphertext was made in, as `open_impl` hashes what it loaded: the
        /// ciphertext is stored and never read back. (The code before read each group back from memory one group later to
        /// hash it; under macOS on an Apple M5 its time depended a little on the plaintext, about 0.2 ns per KiB more for
        /// random bytes than for zeros, where the two-pass code showed none. This kernel halves that, at the same speed; the
        /// rest, about 0.1 ns, is kept as known: B-24, `seal_impl_reload`.)
        #[target_feature(enable = "neon,aes")]
        unsafe fn seal_impl<const NR: usize>(rk: &[[u8; 16]; 15], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, NR);
            let base = nonce_base(nonce);
            let ej0 = tag_mask::<NR>(&rks, base);
            let h = load_powers(pow);
            let mut acc = absorb(vdupq_n_u8(0), aad, &h);
            let total = data.len();
            let p0 = data.as_mut_ptr();
            let mut ctr = 2u32;
            let mut off = 0usize;
            while total - off >= 128 {
                let p = p0.add(off);
                let ks = keystream8::<NR>(&rks, base, ctr);
                let mut x = [vdupq_n_u8(0); 8];
                for (i, k) in ks.iter().enumerate() {
                    let q = p.add(16 * i);
                    let c = veorq_u8(vld1q_u8(q), *k);
                    vst1q_u8(q, c);
                    x[i] = rbit(c);
                }
                acc = ghash8(acc, &x, &h);
                off += 128;
                ctr = ctr.wrapping_add(8);
            }
            let rem = total - off;
            if rem > 0 {
                // the last whole blocks in place, from registers, and a last partial block through 16 bytes on the stack
                // (B-103: a 128-byte buffer copied in and out and wiped byte by byte was about a third of a 100-byte seal)
                let ks = keystream8::<NR>(&rks, base, ctr);
                let (full, part) = (rem / 16, rem % 16);
                let mut x = [vdupq_n_u8(0); 8];
                let p = p0.add(off);
                for i in 0..full {
                    let q = p.add(16 * i);
                    let c = veorq_u8(vld1q_u8(q), ks[i]);
                    vst1q_u8(q, c);
                    x[i] = rbit(c);
                }
                if part > 0 {
                    let tail = &mut data[off + 16 * full..];
                    let mut b = [0u8; 16];
                    b[..part].copy_from_slice(tail);
                    vst1q_u8(b.as_mut_ptr(), veorq_u8(vld1q_u8(b.as_ptr()), ks[full]));
                    tail.copy_from_slice(&b[..part]);
                    // what is hashed is the ciphertext and zeros: the keystream over the padding is dropped
                    b[part..].fill(0);
                    x[full] = rbit(vld1q_u8(b.as_ptr()));
                    b.zeroize();
                }
                acc = ghash_n(acc, &x, rem.div_ceil(16), &h);
            }
            finish(acc, aad.len(), total, &h, ej0)
        }

        /// The seal as it was from B-85 until the timing tests (test builds only, behind `SEAL_BY_RELOAD`): each group's
        /// ciphertext is stored, then read back from memory one group later and hashed while the next group is encrypted.
        #[cfg(test)]
        #[target_feature(enable = "neon,aes")]
        unsafe fn seal_impl_reload<const NR: usize>(rk: &[[u8; 16]; 15], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, NR);
            let base = nonce_base(nonce);
            let ej0 = tag_mask::<NR>(&rks, base);
            let h = load_powers(pow);
            let mut acc = absorb(vdupq_n_u8(0), aad, &h);
            let total = data.len();
            let p0 = data.as_mut_ptr();
            let mut ctr = 2u32;
            let mut off = 0usize;
            // the group encrypted last time round, whose ciphertext is hashed while this one is being encrypted
            let mut prev: Option<usize> = None;
            while total - off >= 128 {
                let p = p0.add(off);
                let ks = keystream8::<NR>(&rks, base, ctr);
                for (i, k) in ks.iter().enumerate() {
                    let q = p.add(16 * i);
                    vst1q_u8(q, veorq_u8(vld1q_u8(q), *k));
                }
                if let Some(o) = prev {
                    acc = ghash8(acc, &load8_poly(p0.add(o)), &h);
                }
                prev = Some(off);
                off += 128;
                ctr = ctr.wrapping_add(8);
            }
            if let Some(o) = prev {
                acc = ghash8(acc, &load8_poly(p0.add(o)), &h);
            }
            let rem = total - off;
            if rem > 0 {
                let mut buf = [0u8; 128];
                buf[..rem].copy_from_slice(&data[off..]);
                let ks = keystream8::<NR>(&rks, base, ctr);
                for (i, k) in ks.iter().enumerate() {
                    let q = buf.as_mut_ptr().add(16 * i);
                    vst1q_u8(q, veorq_u8(vld1q_u8(q), *k));
                }
                data[off..].copy_from_slice(&buf[..rem]);
                // what is hashed is the ciphertext and zeros: the keystream over the padding is dropped
                buf[rem..].fill(0);
                acc = ghash_n(acc, &load8_poly(buf.as_ptr()), rem.div_ceil(16), &h);
                buf.zeroize();
            }
            finish(acc, aad.len(), total, &h, ej0)
        }

        /// Decrypts `data` in place (counters from 2) and returns the tag the ciphertext it was should have: the GHASH
        /// value S of `aad` and that ciphertext, masked with E(J0). (The caller checks the tag, and puts the ciphertext back
        /// if it is wrong.)
        #[target_feature(enable = "neon,aes")]
        unsafe fn open_impl<const NR: usize>(rk: &[[u8; 16]; 15], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            use crate::zeroize::Zeroize;
            let rks = load_keys(rk, NR);
            let base = nonce_base(nonce);
            let ej0 = tag_mask::<NR>(&rks, base);
            let h = load_powers(pow);
            let mut acc = absorb(vdupq_n_u8(0), aad, &h);
            let total = data.len();
            let p0 = data.as_mut_ptr();
            let mut ctr = 2u32;
            let mut off = 0usize;
            while total - off >= 128 {
                let p = p0.add(off);
                let mut c = [vdupq_n_u8(0); 8];
                for (i, v) in c.iter_mut().enumerate() {
                    *v = vld1q_u8(p.add(16 * i));
                }
                // the hash of the ciphertext and the keystream do not depend on each other
                let mut x = c;
                for v in x.iter_mut() {
                    *v = rbit(*v);
                }
                acc = ghash8(acc, &x, &h);
                let ks = keystream8::<NR>(&rks, base, ctr);
                for i in 0..8 {
                    vst1q_u8(p.add(16 * i), veorq_u8(c[i], ks[i]));
                }
                off += 128;
                ctr = ctr.wrapping_add(8);
            }
            let rem = total - off;
            if rem > 0 {
                // as in `seal_impl`: whole blocks in place, a partial one through 16 bytes on the stack
                let (full, part) = (rem / 16, rem % 16);
                let p = p0.add(off);
                let mut c = [vdupq_n_u8(0); 8];
                for (i, v) in c.iter_mut().enumerate().take(full) {
                    *v = vld1q_u8(p.add(16 * i));
                }
                let mut b = [0u8; 16];
                if part > 0 {
                    b[..part].copy_from_slice(&data[off + 16 * full..]);
                    c[full] = vld1q_u8(b.as_ptr());
                }
                let mut x = c;
                for v in x.iter_mut() {
                    *v = rbit(*v);
                }
                acc = ghash_n(acc, &x, rem.div_ceil(16), &h);
                let ks = keystream8::<NR>(&rks, base, ctr);
                for i in 0..full {
                    vst1q_u8(p.add(16 * i), veorq_u8(c[i], ks[i]));
                }
                if part > 0 {
                    vst1q_u8(b.as_mut_ptr(), veorq_u8(c[full], ks[full]));
                    data[off + 16 * full..].copy_from_slice(&b[..part]);
                    b.zeroize();
                }
            }
            finish(acc, aad.len(), total, &h, ej0)
        }

        /// # Safety
        /// The CPU must support the ARMv8 AES and PMULL instructions. `nr` is 10 or 14.
        pub(super) unsafe fn gcm_seal(rk: &[[u8; 16]; 15], nr: usize, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            #[cfg(test)]
            if super::super::SEAL_BY_RELOAD.with(std::cell::Cell::get) {
                return match nr {
                    10 => seal_impl_reload::<10>(rk, nonce, aad, data, pow),
                    14 => seal_impl_reload::<14>(rk, nonce, aad, data, pow),
                    _ => unreachable!("AES keys have 10 or 14 rounds"),
                };
            }
            match nr {
                10 => seal_impl::<10>(rk, nonce, aad, data, pow),
                14 => seal_impl::<14>(rk, nonce, aad, data, pow),
                _ => unreachable!("AES keys have 10 or 14 rounds"),
            }
        }

        /// # Safety
        /// As for [`gcm_seal`].
        pub(super) unsafe fn gcm_open(rk: &[[u8; 16]; 15], nr: usize, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &[u128; 8]) -> [u8; 16] {
            match nr {
                10 => open_impl::<10>(rk, nonce, aad, data, pow),
                14 => open_impl::<14>(rk, nonce, aad, data, pow),
                _ => unreachable!("AES keys have 10 or 14 rounds"),
            }
        }

        /// 64 x 64 -> 128 bit carry-less product (PMULL).
        ///
        /// # Safety
        /// The CPU must support PMULL on 64-bit operands (the `aes` feature).
        #[target_feature(enable = "neon,aes")]
        #[inline]
        pub(crate) unsafe fn clmul64(a: u64, b: u64) -> u128 {
            vmull_p64(a, b)
        }

        /// # Safety
        /// The CPU must support PMULL on 64-bit operands (the `aes` feature).
        #[target_feature(enable = "neon,aes")]
        pub(super) unsafe fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
            crate::crypto::ghash::hash_with::<true>(h, aad, ct)
        }
    }

    pub(crate) use arch::clmul64;

    /// The expanded key as round-key bytes, which the instructions load directly.
    #[derive(Clone)]
    pub(crate) struct Keys {
        rk: [[u8; 16]; aes_ct::MAX_ROUND_KEYS],
        rounds: usize,
    }

    impl Drop for Keys {
        fn drop(&mut self) {
            self.wipe();
        }
    }

    impl Keys {
        /// Panics if the hardware path is not [`available`].
        pub(crate) fn new(key: &[u8]) -> Keys {
            assert!(available(), "hardware AES is not available on this CPU");
            Keys::new_unchecked(key)
        }

        fn new_unchecked(key: &[u8]) -> Keys {
            // the key schedule is the constant-time portable one, so a key never touches a table
            let (rk, rounds) = aes_ct::expand_key(key);
            Keys { rk, rounds }
        }

        pub(crate) fn wipe(&mut self) {
            self.rk.zeroize();
            self.rounds = 0;
        }

        #[cfg(test)]
        pub(crate) fn is_wiped(&self) -> bool {
            self.rounds == 0 && self.rk.iter().flatten().all(|&b| b == 0)
        }

        pub(crate) fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
            debug_assert!(self.rounds != 0, "key was wiped");
            // SAFETY: a `Keys` exists only if `available()` was true (`new`) or if the self-test
            // is checking the CPU features itself (`new_unchecked` in `selftest`).
            unsafe { arch::encrypt_block(&self.rk, self.rounds, block) }
        }

        pub(crate) fn ctr_xor(&self, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
            debug_assert!(self.rounds != 0, "key was wiped");
            // SAFETY: as in `encrypt_block`.
            unsafe { arch::ctr_xor(&self.rk, self.rounds, nonce, counter, data) }
        }
    }

    /// GHASH of `aad` and `ct` under the reflected hash key `h` (see [`ghash`]), on the CPU's
    /// carry-less multiplier. Panics if the hardware path is not available.
    pub(crate) fn ghash_hw(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
        assert!(available(), "hardware GHASH is not available on this CPU");
        // SAFETY: `available()` implies PCLMULQDQ / PMULL.
        unsafe { arch::ghash(h, aad, ct) }
    }

    /// H^1 ... H^8 for the hash subkey block, which the one-pass GCM below needs (byte-reversed on x86-64, the bits of
    /// each byte reversed on aarch64: each architecture's own form). Both architectures have the one-pass path since B-85;
    /// the `Option` stays for the builds that have none.
    pub(crate) type Powers = [u128; 8];

    pub(crate) fn ghash_powers(h: &[u8; 16]) -> Option<Powers> {
        assert!(available(), "hardware GHASH is not available on this CPU");
        // SAFETY: `available()` implies the instructions (PCLMULQDQ and SSSE3, or PMULL).
        Some(unsafe { arch::powers(h) })
    }

    impl Keys {
        /// AES-GCM encryption in one pass over `data` (in place, counters from 2): the tag (the GHASH value S of `aad` and
        /// the ciphertext, masked with E(J0)), or `None` where this CPU has no one-pass path (the caller then does the two
        /// steps).
        pub(crate) fn gcm_seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &Powers) -> Option<[u8; 16]> {
            debug_assert!(self.rounds != 0, "key was wiped");
            // SAFETY: as in `encrypt_block`; the powers exist only where `available()` was true.
            Some(unsafe { arch::gcm_seal(&self.rk, self.rounds, nonce, aad, data, pow) })
        }

        /// The same for decryption: `data` becomes the plaintext, and the tag returned is the one the ciphertext it was
        /// should have. It is not checked here: if the message's is not that, the caller must put the ciphertext back
        /// (`ctr_xor` again does).
        pub(crate) fn gcm_open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], pow: &Powers) -> Option<[u8; 16]> {
            debug_assert!(self.rounds != 0, "key was wiped");
            // SAFETY: as in `gcm_seal`.
            Some(unsafe { arch::gcm_open(&self.rk, self.rounds, nonce, aad, data, pow) })
        }
    }

    /// Whether this CPU has the instructions at all (without the self-test).
    pub(crate) fn cpu_supports() -> bool {
        arch::cpu_supports()
    }

    static AVAILABLE: OnceLock<bool> = OnceLock::new();

    /// True if the hardware path may be used: the CPU has the instructions and the self-test passed.
    pub(crate) fn available() -> bool {
        *AVAILABLE.get_or_init(|| cpu_supports() && selftest())
    }

    /// Known answers for AES, and the hardware CTR and GHASH against the portable code.
    fn selftest() -> bool {
        // FIPS 197 appendix C.1 and C.3
        let pt: [u8; 16] = core::array::from_fn(|i| (0x11 * i) as u8);
        let k128: [u8; 16] = core::array::from_fn(|i| i as u8);
        let k256: [u8; 32] = core::array::from_fn(|i| i as u8);
        let ct128 = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
        let ct256 = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
        if Keys::new_unchecked(&k128).encrypt_block(&pt) != ct128 || Keys::new_unchecked(&k256).encrypt_block(&pt) != ct256 {
            return false;
        }
        // CTR: lengths around the 8-block unrolling, a wrapping counter, both key sizes
        let nonce: [u8; 12] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        for key in [&k128[..], &k256[..]] {
            let hw = Keys::new_unchecked(key);
            let soft = Aes::with_backend(key, Backend::Portable);
            for len in [0usize, 5, 16, 100, 128, 131, 300] {
                let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                let (mut a, mut b) = (data.clone(), data);
                hw.ctr_xor(&nonce, 0xffff_fffd, &mut a);
                soft.ctr_xor(&nonce, 0xffff_fffd, &mut b);
                if a != b {
                    return false;
                }
            }
        }
        // GHASH with a hash key and data that exercise every bit position
        let h = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128 ^ ((0xe100_0000_0000_0000_u128) << 64);
        let aad: Vec<u8> = (0..21).map(|i| (i * 13 + 5) as u8).collect();
        let ct: Vec<u8> = (0..70).map(|i| (i * 29 + 3) as u8).collect();
        // SAFETY: `cpu_supports()` was true on the way into the self-test
        let hw = unsafe { arch::ghash(h, &aad, &ct) };
        if hw != ghash::hash_with::<false>(h, &aad, &ct) {
            return false;
        }
        one_pass_matches_the_portable_code(&k128, SELFTEST_LENGTHS, SELFTEST_AAD_LENGTHS)
            && one_pass_matches_the_portable_code(&k256, SELFTEST_LENGTHS, SELFTEST_AAD_LENGTHS)
    }

    /// What the self-test (which runs once in every process that uses AES-GCM, before its first record) tries the
    /// one-pass GCM on: one length for each way through the code (empty, a partial block, a block and a bit, exactly a
    /// group of eight blocks, a group and a tail, a few groups and a tail) and additional data of the sizes TLS uses
    /// (none, and the 5 bytes of a record header) and a longer one. The portable code it is compared with is the slow
    /// constant-time one, so the sweep over every length is a unit test (`one_pass_matches_the_portable_code_for_all_the_lengths`)
    /// and not part of every process's start.
    const SELFTEST_LENGTHS: &[usize] = &[0, 17, 128, 257, 1000];
    const SELFTEST_AAD_LENGTHS: &[usize] = &[0, 5, 130];

    /// The one-pass GCM against the portable CTR and GHASH: the tag and the data, both ways, for the given lengths of
    /// data and of additional data.
    fn one_pass_matches_the_portable_code(key: &[u8], lens: &[usize], aad_lens: &[usize]) -> bool {
        let soft = Aes::with_backend(key, Backend::Portable);
        let h_block = soft.encrypt_block(&[0u8; 16]);
        let h = u128::from_be_bytes(h_block).reverse_bits();
        // SAFETY: `cpu_supports()` was true on the way into the self-test
        let pow = unsafe { arch::powers(&h_block) };
        let hw = Keys::new_unchecked(key);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i * 11 + 3) as u8);
        for &len in lens {
            for &aad_len in aad_lens {
                let aad: Vec<u8> = (0..aad_len).map(|i| (i * 13 + 5) as u8).collect();
                let plain: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                // the portable code: CTR from 2, then GHASH of the ciphertext
                let mut want = plain.clone();
                soft.ctr_xor(&nonce, 2, &mut want);
                let mut j0 = [0u8; 16];
                j0[..12].copy_from_slice(&nonce);
                j0[15] = 1;
                let ej0 = soft.encrypt_block(&j0);
                let s = ghash::hash_with::<false>(h, &aad, &want).to_be_bytes();
                let want_tag: [u8; 16] = core::array::from_fn(|i| s[i] ^ ej0[i]);
                // SAFETY: as above
                let mut sealed = plain.clone();
                let tag = unsafe { arch::gcm_seal(&hw.rk, hw.rounds, &nonce, &aad, &mut sealed, &pow) };
                if sealed != want || tag != want_tag {
                    return false;
                }
                let mut opened = want.clone();
                // SAFETY: as above
                let tag = unsafe { arch::gcm_open(&hw.rk, hw.rounds, &nonce, &aad, &mut opened, &pow) };
                if opened != plain || tag != want_tag {
                    return false;
                }
            }
        }
        true
    }

    /// Every length around the groups of eight blocks and the usual sizes of additional data, both key sizes: the
    /// sweep the start-up self-test is a sample of.
    #[cfg(test)]
    #[test]
    fn one_pass_matches_the_portable_code_for_all_the_lengths() {
        if !cpu_supports() {
            return;
        }
        let k128: [u8; 16] = core::array::from_fn(|i| i as u8);
        let k256: [u8; 32] = core::array::from_fn(|i| i as u8);
        let lens = [0usize, 1, 15, 16, 17, 100, 127, 128, 129, 255, 256, 257, 1000, 2049];
        let aads = [0usize, 5, 16, 29, 130];
        assert!(one_pass_matches_the_portable_code(&k128, &lens, &aads));
        assert!(one_pass_matches_the_portable_code(&k256, &lens, &aads));
    }
}

#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), not(pratique_portable)))]
pub(crate) use real::{available, clmul64, ghash_hw, ghash_powers, Keys, Powers};
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64"), not(pratique_portable)))]
pub(crate) use real::cpu_supports;

/// The same API for builds without the hardware path: never available, and `Keys` cannot exist.
#[cfg(not(all(any(target_arch = "x86_64", target_arch = "aarch64"), not(pratique_portable))))]
#[allow(dead_code)]
mod none {
    #[derive(Clone)]
    pub(crate) enum Keys {}

    impl Keys {
        pub(crate) fn new(_key: &[u8]) -> Keys {
            panic!("hardware AES is not available in this build")
        }
        pub(crate) fn wipe(&mut self) {
            match *self {}
        }
        #[cfg(test)]
        pub(crate) fn is_wiped(&self) -> bool {
            match *self {}
        }
        pub(crate) fn encrypt_block(&self, _block: &[u8; 16]) -> [u8; 16] {
            match *self {}
        }
        pub(crate) fn ctr_xor(&self, _nonce: &[u8; 12], _counter: u32, _data: &mut [u8]) {
            match *self {}
        }
        pub(crate) fn gcm_seal(&self, _nonce: &[u8; 12], _aad: &[u8], _data: &mut [u8], _pow: &Powers) -> Option<[u8; 16]> {
            match *self {}
        }
        pub(crate) fn gcm_open(&self, _nonce: &[u8; 12], _aad: &[u8], _data: &mut [u8], _pow: &Powers) -> Option<[u8; 16]> {
            match *self {}
        }
    }

    pub(crate) type Powers = [u128; 8];

    pub(crate) fn ghash_powers(_h: &[u8; 16]) -> Option<Powers> {
        None
    }

    pub(crate) fn available() -> bool {
        false
    }

    #[cfg(test)]
    pub(crate) fn cpu_supports() -> bool {
        false
    }

    pub(crate) fn ghash_hw(_h: u128, _aad: &[u8], _ct: &[u8]) -> u128 {
        unreachable!("hardware GHASH is not available in this build")
    }

    /// # Safety
    /// Never callable: only reached through `hash_with::<true>`, which needs [`available`].
    pub(crate) unsafe fn clmul64(_a: u64, _b: u64) -> u128 {
        unreachable!("hardware carry-less multiplication is not available in this build")
    }
}

#[cfg(not(all(any(target_arch = "x86_64", target_arch = "aarch64"), not(pratique_portable))))]
pub(crate) use none::{available, clmul64, ghash_hw, ghash_powers, Keys, Powers};
#[cfg(all(test, not(all(any(target_arch = "x86_64", target_arch = "aarch64"), not(pratique_portable)))))]
pub(crate) use none::cpu_supports;
