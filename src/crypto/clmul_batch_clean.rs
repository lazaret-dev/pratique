//! Independently derived 64-lane Boolean polynomial products for portable GHASH.
//!
//! Primitive expressions and borrowed preparation come from the committed
//! clean-only experiment (lifecycle API 5ecf2525). Only experiment-only APIs/tests
//! were omitted and module placement changed. See the clean-room and integration
//! provenance. Object moves and compiler spills remain a best-effort wiping limit.
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

/// Involutory 64 by 64 bit-matrix transpose in the caller's retained storage.
#[inline(never)]
pub fn transpose_in_place(q: &mut [u64; 64]) {
    transpose_step::<1>(q, 0x5555_5555_5555_5555);
    transpose_step::<2>(q, 0x3333_3333_3333_3333);
    transpose_step::<4>(q, 0x0f0f_0f0f_0f0f_0f0f);
    transpose_step::<8>(q, 0x00ff_00ff_00ff_00ff);
    transpose_step::<16>(q, 0x0000_ffff_0000_ffff);
    transpose_step::<32>(q, 0x0000_0000_ffff_ffff);
}

/// Value wrapper for working data; key preparation uses the in-place API.
#[inline(never)]
pub fn transpose(mut q: [u64; 64]) -> [u64; 64] {
    transpose_in_place(&mut q);
    q
}

/// Retained transposed coefficients for a fixed 64-lane batch.
#[derive(Clone)]
pub struct Prepared64([u64; 64]);

impl Prepared64 {
    /// Construct zero storage before any key material enters the destination.
    pub const fn empty() -> Self {
        Self([0; 64])
    }

    /// Populate retained storage from a caller-owned input, without scratch arrays.
    /// The caller remains responsible for wiping the source when appropriate.
    #[allow(dead_code)] // Shared borrowed API; wide preparation writes its retained fields directly.
    pub fn prepare(&mut self, b: &[u64; 64]) {
        self.0.copy_from_slice(b);
        transpose_in_place(&mut self.0);
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
/// The owning production key zeroizes all stored words on destruction.
#[derive(Clone)]
pub struct PreparedPolynomial128x64 {
    low: Prepared64,
    high: Prepared64,
    mixed: Prepared64,
}

impl PreparedPolynomial128x64 {
    /// Return only zero state; retained key material is initialized in place.
    pub const fn empty() -> Self {
        Self {
            low: Prepared64::empty(),
            high: Prepared64::empty(),
            mixed: Prepared64::empty(),
        }
    }

    /// Borrow the caller's raw powers and fill the destination's planes directly.
    ///
    /// No source-owned intermediate key arrays or populated return value are
    /// created. Caller-owned raw powers still require the caller's zeroization.
    /// This does not promise erasure of compiler-generated moves/register spills.
    pub fn prepare(&mut self, b: &[u128; 64]) {
        for i in 0..64 {
            self.low.0[i] = b[i] as u64;
            self.high.0[i] = (b[i] >> 64) as u64;
            self.mixed.0[i] = self.low.0[i] ^ self.high.0[i];
        }
        transpose_in_place(&mut self.low.0);
        transpose_in_place(&mut self.high.0);
        transpose_in_place(&mut self.mixed.0);
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

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn borrowed_preparation_keeps_retained_storage_and_input() {
        let input = core::array::from_fn(|i| {
            (u128::from(i as u64 + 1) << 96) ^ u128::from(0x9e37_79b9_7f4a_7c15u64 ^ i as u64)
        });
        let expected_input = input; // Synthetic test fixture only.
        let mut prepared = PreparedPolynomial128x64::empty();
        assert!(prepared
            .words()
            .iter()
            .all(|words| words.iter().all(|&x| x == 0)));
        let addresses = prepared.words().map(|words| words.as_ptr() as usize);
        let prepare: fn(&mut PreparedPolynomial128x64, &[u128; 64]) =
            PreparedPolynomial128x64::prepare;
        prepare(&mut prepared, &input);
        assert_eq!(
            prepared.words().map(|words| words.as_ptr() as usize),
            addresses
        );
        assert_eq!(input, expected_input);
        assert!(prepared
            .words()
            .iter()
            .any(|words| words.iter().any(|&x| x != 0)));
        prepared.prepare(&[0; 64]);
        assert_eq!(
            prepared.words().map(|words| words.as_ptr() as usize),
            addresses
        );
        assert!(prepared
            .words()
            .iter()
            .all(|words| words.iter().all(|&x| x == 0)));
    }

    #[test]
    fn narrow_borrowed_preparation_also_overwrites_in_place() {
        let input = core::array::from_fn(|i| 0x6a09_e667_f3bc_c909u64 ^ i as u64);
        let mut prepared = Prepared64::empty();
        let address = prepared.0.as_ptr();
        let prepare: fn(&mut Prepared64, &[u64; 64]) = Prepared64::prepare;
        prepare(&mut prepared, &input);
        assert_eq!(prepared.0.as_ptr(), address);
        assert_eq!(prepared.0, transpose(input));
        prepared.prepare(&[0; 64]);
        assert_eq!(prepared.0.as_ptr(), address);
        assert_eq!(prepared.0, [0; 64]);
    }
}
