//! Independently derived 64-lane Boolean polynomial products for portable GHASH.
//!
//! The primitive expressions are copied unchanged from the separately committed
//! clean-room experiment (2a1d8553, lifecycle accessors from bede170a).
//! Only experiment-only APIs/tests were omitted and module placement changed.
//! See cleanroom/clmul_feasibility/PROVENANCE.md and the integration provenance.
#![forbid(unsafe_code)]

#[path = "clmul_batch_circuit.rs"]
mod circuit;

#[inline(always)]
fn transpose_step<const SHIFT: usize>(q: &mut [u64; 64], mask: u64) {
    for block in (0..64).step_by(SHIFT << 1) {
        for j in 0..SHIFT {
            let lo = block + j;
            let hi = lo + SHIFT;
            let exchanged = ((q[lo] >> SHIFT) ^ q[hi]) & mask;
            q[lo] ^= exchanged << SHIFT;
            q[hi] ^= exchanged;
        }
    }
}

/// Involutory 64 by 64 bit-matrix transpose, with fixed addresses.
#[inline(never)]
pub fn transpose(mut q: [u64; 64]) -> [u64; 64] {
    transpose_step::<1>(&mut q, 0x5555_5555_5555_5555);
    transpose_step::<2>(&mut q, 0x3333_3333_3333_3333);
    transpose_step::<4>(&mut q, 0x0f0f_0f0f_0f0f_0f0f);
    transpose_step::<8>(&mut q, 0x00ff_00ff_00ff_00ff);
    transpose_step::<16>(&mut q, 0x0000_ffff_0000_ffff);
    transpose_step::<32>(&mut q, 0x0000_0000_ffff_ffff);
    q
}

/// Transposed polynomial coefficients for a fixed 64-lane batch.
#[derive(Clone)]
pub struct Prepared64([u64; 64]);

impl Prepared64 {
    pub fn new(b: [u64; 64]) -> Self {
        Self(transpose(b))
    }
}

/// XOR of 64 unreduced products against one prepared operand set.
#[inline(never)]
pub fn clmul64_batch_xor_prepared(a: [u64; 64], b: &Prepared64) -> u128 {
    let p = circuit::planes_product(&transpose(a), &b.0);
    let mut low = 0u64;
    let mut high = 0u64;
    for bit in 0..64 {
        low ^= u64::from(p[bit].count_ones() & 1) << bit;
        high ^= u64::from(p[bit + 64].count_ones() & 1) << bit;
    }
    u128::from(low) ^ (u128::from(high) << 64)
}

/// Three prepared operand sets for 64 independent 128-bit polynomial products.
/// The production GHASH key owns and zeroizes these buffers.
#[derive(Clone)]
pub struct PreparedPolynomial128x64 {
    low: Prepared64,
    high: Prepared64,
    mixed: Prepared64,
}

impl PreparedPolynomial128x64 {
    pub fn new(b: [u128; 64]) -> Self {
        let mut low = [0; 64];
        let mut high = [0; 64];
        let mut mixed = [0; 64];
        for i in 0..64 {
            low[i] = b[i] as u64;
            high[i] = (b[i] >> 64) as u64;
            mixed[i] = low[i] ^ high[i];
        }
        Self {
            low: Prepared64::new(low),
            high: Prepared64::new(high),
            mixed: Prepared64::new(mixed),
        }
    }

    /// Expose all prepared secret words to the caller's existing zeroization.
    pub(crate) fn words_mut(&mut self) -> [&mut [u64; 64]; 3] {
        [&mut self.low.0, &mut self.high.0, &mut self.mixed.0]
    }

    #[cfg(test)]
    pub(crate) fn words(&self) -> [&[u64; 64]; 3] {
        [&self.low.0, &self.high.0, &self.mixed.0]
    }
}

/// Return the XOR of 64 unreduced 128 by 128 polynomial products.
/// The return value is [low 128 bits, high 128 bits], with no field reduction.
#[inline(never)]
pub fn clmul128_batch_xor_prepared(a: [u128; 64], b: &PreparedPolynomial128x64) -> [u128; 2] {
    let mut low = [0; 64];
    let mut high = [0; 64];
    let mut mixed = [0; 64];
    for i in 0..64 {
        low[i] = a[i] as u64;
        high[i] = (a[i] >> 64) as u64;
        mixed[i] = low[i] ^ high[i];
    }
    let p0 = clmul64_batch_xor_prepared(low, &b.low);
    let p1 = clmul64_batch_xor_prepared(high, &b.high);
    let pm = clmul64_batch_xor_prepared(mixed, &b.mixed) ^ p0 ^ p1;
    [p0 ^ (pm << 64), p1 ^ (pm >> 64)]
}
