//! Independently derived 64-lane Boolean polynomial products for portable GHASH.
//!
//! The borrowed preparation and working-state APIs are copied from committed
//! clean-only lifecycle sources (27a1c8ac). The production caller owns all work
//! arrays and applies its existing volatile zeroization after their final use.
//! Object moves, scalar circuit nodes, registers and compiler spills remain a
//! best-effort wiping limit. No populated aggregate returns on the used path.
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
    #[allow(dead_code)] // Shared narrow API; wide preparation fills retained fields directly.
    pub fn prepare(&mut self, b: &[u64; 64]) {
        self.0.copy_from_slice(b);
        transpose_in_place(&mut self.0);
    }
}

/// XOR of 64 unreduced products, useful only if an integrator changes scheduling.
/// Preparation is excluded from this call and must be measured separately.
#[inline(never)]
pub fn clmul64_batch_xor_prepared(
    a: &mut [u64; 64],
    b: &Prepared64,
    product_planes: &mut [u64; 128],
    result: &mut u128,
) {
    transpose_in_place(a);
    circuit::planes_product(a, &b.0, product_planes);
    let mut low = 0u64;
    let mut high = 0u64;
    for bit in 0..64 {
        low ^= u64::from(product_planes[bit].count_ones() & 1) << bit;
        high ^= u64::from(product_planes[bit + 64].count_ones() & 1) << bit;
    }
    *result = u128::from(low) ^ (u128::from(high) << 64);
}

/// Three prepared operand sets for 64 independent 128-bit polynomial products.
/// The production key owner zeroizes all retained words.
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

/// Caller-owned aggregates used by the prepared polynomial product.
///
/// Construct this zero state before processing secret-derived data. The caller
/// must wipe every slice exposed by `words64_mut` and `words128_mut` after its
/// final use of `output`. There is no populated workspace return or Clone/Copy
/// implementation. The circuit's scalar temporaries and compiler-generated
/// moves, registers and spills are outside this source-owned aggregate claim.
pub struct BatchWorking128x64 {
    low: [u64; 64],
    high: [u64; 64],
    mixed: [u64; 64],
    product_planes: [u64; 128],
    sums: [u128; 3],
    output: [u128; 2],
}

impl BatchWorking128x64 {
    /// Return only zero storage; populate the retained destination in place.
    pub const fn empty() -> Self {
        Self {
            low: [0; 64],
            high: [0; 64],
            mixed: [0; 64],
            product_planes: [0; 128],
            sums: [0; 3],
            output: [0; 2],
        }
    }

    /// Borrow [low 128 bits, high 128 bits] of the unreduced product XOR.
    pub fn output(&self) -> &[u128; 2] {
        &self.output
    }

    /// Expose every 64-bit aggregate to the caller's volatile zeroization.
    pub fn words64_mut(&mut self) -> [&mut [u64]; 4] {
        [
            &mut self.low,
            &mut self.high,
            &mut self.mixed,
            &mut self.product_planes,
        ]
    }

    /// Expose every 128-bit aggregate, including results, for caller wiping.
    pub fn words128_mut(&mut self) -> [&mut [u128]; 2] {
        [&mut self.sums, &mut self.output]
    }
}

/// Write the XOR of 64 unreduced 128 by 128 products in caller-owned storage.
/// The raw block input is borrowed and remains the caller's wiping obligation.
#[inline(never)]
pub fn clmul128_batch_xor_prepared(
    a: &[u128; 64],
    b: &PreparedPolynomial128x64,
    working: &mut BatchWorking128x64,
) {
    for i in 0..64 {
        working.low[i] = a[i] as u64;
        working.high[i] = (a[i] >> 64) as u64;
        working.mixed[i] = working.low[i] ^ working.high[i];
    }
    clmul64_batch_xor_prepared(
        &mut working.low,
        &b.low,
        &mut working.product_planes,
        &mut working.sums[0],
    );
    clmul64_batch_xor_prepared(
        &mut working.high,
        &b.high,
        &mut working.product_planes,
        &mut working.sums[1],
    );
    clmul64_batch_xor_prepared(
        &mut working.mixed,
        &b.mixed,
        &mut working.product_planes,
        &mut working.sums[2],
    );
    working.sums[2] ^= working.sums[0] ^ working.sums[1];
    working.output[0] = working.sums[0] ^ (working.sums[2] << 64);
    working.output[1] = working.sums[1] ^ (working.sums[2] >> 64);
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
        let mut expected = input;
        transpose_in_place(&mut expected);
        assert_eq!(prepared.0, expected);
        prepared.prepare(&[0; 64]);
        assert_eq!(prepared.0.as_ptr(), address);
        assert_eq!(prepared.0, [0; 64]);
    }
}
