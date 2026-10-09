//! Variable-length unsigned integers and Montgomery modular arithmetic.
//!
//! This is only used on PUBLIC data (signature verification: RSA moduli,
//! curve points, signatures), so it is not constant time: the loops run as long as the exponent, `cmp` and
//! `is_zero` stop at the first difference, and the reductions branch on magnitudes. That is why the module is
//! private to the crate; no secret may go through its arithmetic (the constant-time code in `ecdh.rs` and
//! `x25519.rs` does its own, and uses this module for constants, conversions and public values; see the notes there).
//!
//! Numbers are little-endian `u64` limb vectors. Functions that take a modulus
//! expect operands that are already reduced and exactly as long as the modulus.

use std::cmp::Ordering;

/// Parses big-endian bytes into little-endian limbs (not trimmed).
pub fn from_be_bytes(bytes: &[u8]) -> Vec<u64> {
    let n = (bytes.len() + 7) / 8;
    let mut limbs = vec![0u64; n.max(1)];
    for (i, b) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (*b as u64) << (8 * (i % 8));
    }
    limbs
}

/// Serialises to exactly `len` big-endian bytes (panics if the value does not fit).
pub fn to_be_bytes(limbs: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..limbs.len() * 8 {
        let byte = (limbs[i / 8] >> (8 * (i % 8))) as u8;
        if i < len {
            out[len - 1 - i] = byte;
        } else {
            assert!(byte == 0, "value does not fit");
        }
    }
    out
}

#[allow(dead_code)] // the constants of ecdh.rs (the `net` part) are written in hex
pub fn from_hex(s: &str) -> Vec<u64> {
    from_be_bytes(&crate::util::unhex(s))
}

pub fn trimmed_len(a: &[u64]) -> usize {
    let mut n = a.len();
    while n > 0 && a[n - 1] == 0 {
        n -= 1;
    }
    n
}

#[allow(dead_code)] // only the tests of the other modules use it
pub fn is_zero(a: &[u64]) -> bool {
    a.iter().all(|&x| x == 0)
}

pub fn bit_len(a: &[u64]) -> usize {
    let n = trimmed_len(a);
    if n == 0 {
        0
    } else {
        64 * n - a[n - 1].leading_zeros() as usize
    }
}

pub fn bit(a: &[u64], i: usize) -> bool {
    a.get(i / 64).map_or(false, |l| (l >> (i % 64)) & 1 == 1)
}

/// Compares numerically; operands may have different lengths.
pub fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// a += b (same length); returns the carry out.
fn add_in_place(a: &mut [u64], b: &[u64]) -> bool {
    let mut carry = 0u64;
    for i in 0..a.len() {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        a[i] = s2;
        carry = (c1 | c2) as u64;
    }
    carry != 0
}

/// a -= b (same length); returns the borrow out.
fn sub_in_place(a: &mut [u64], b: &[u64]) -> bool {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    borrow != 0
}

/// Montgomery context for an odd modulus.
#[derive(Clone)]
pub struct Mont {
    m: Vec<u64>,
    n: usize,
    m0inv: u64,
    /// R mod m, i.e. the Montgomery form of 1.
    one: Vec<u64>,
    /// R^2 mod m.
    r2: Vec<u64>,
}

impl Mont {
    /// `modulus` must be odd and greater than 1.
    pub fn new(modulus: &[u64]) -> Mont {
        let n = trimmed_len(modulus);
        assert!(n > 0 && modulus[0] & 1 == 1, "Montgomery modulus must be odd");
        let m = modulus[..n].to_vec();
        // -m^-1 mod 2^64 by Newton iteration
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let m0inv = inv.wrapping_neg();
        let mut ctx = Mont { m, n, m0inv, one: vec![0; n], r2: vec![0; n] };
        if n == 1 && ctx.m[0] == 1 {
            return ctx; // everything is 0 modulo 1
        }
        // R mod m: the highest power of two below m, doubled up to 2^(64n) (at most 64 doublings)
        let bits = bit_len(&ctx.m);
        let mut x = vec![0u64; n];
        x[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
        for _ in 0..64 * n - (bits - 1) {
            x = ctx.add(&x, &x);
        }
        ctx.one = x;
        // R^2 mod m = 2^(64n) R mod m, from R (2^0 R) by the bits of 64n, high first: a Montgomery square takes 2^a R
        // to 2^(2a) R and a doubling takes it to 2^(a+1) R. A dozen multiplications instead of 64n modular doublings,
        // which made parsing an RSA-2048 key cost 0.3 ms and an RSA-4096 one over 1 ms.
        let e = 64 * n;
        let mut y = ctx.one.clone();
        for i in (0..usize::BITS - e.leading_zeros()).rev() {
            y = ctx.mul(&y, &y);
            if (e >> i) & 1 == 1 {
                y = ctx.add(&y, &y);
            }
        }
        ctx.r2 = y;
        ctx
    }

    pub fn modulus(&self) -> &[u64] {
        &self.m
    }

    #[allow(dead_code)] // used by ecdh.rs (the `net` part)
    pub fn limbs(&self) -> usize {
        self.n
    }

    /// Pads or checks a value to the modulus length.
    pub fn fit(&self, a: &[u64]) -> Vec<u64> {
        let mut v = a.to_vec();
        assert!(trimmed_len(&v) <= self.n, "value larger than modulus");
        v.resize(self.n, 0);
        v
    }

    /// Montgomery form of 1.
    pub fn one(&self) -> Vec<u64> {
        self.one.clone()
    }

    #[allow(dead_code)] // only the tests use it
    pub fn zero(&self) -> Vec<u64> {
        vec![0; self.n]
    }

    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut r = a.to_vec();
        let carry = add_in_place(&mut r, b);
        if carry || cmp(&r, &self.m) != Ordering::Less {
            sub_in_place(&mut r, &self.m);
        }
        r
    }

    #[allow(dead_code)] // only the tests use it
    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut r = a.to_vec();
        if sub_in_place(&mut r, b) {
            add_in_place(&mut r, &self.m);
        }
        r
    }

    /// Montgomery product: a * b * R^-1 mod m (CIOS).
    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = self.n;
        let m = &self.m;
        let mut t = vec![0u64; n + 2];
        for i in 0..n {
            let mut carry = 0u128;
            for j in 0..n {
                let cur = t[j] as u128 + a[j] as u128 * b[i] as u128 + carry;
                t[j] = cur as u64;
                carry = cur >> 64;
            }
            let cur = t[n] as u128 + carry;
            t[n] = cur as u64;
            t[n + 1] = (cur >> 64) as u64;

            let q = t[0].wrapping_mul(self.m0inv);
            let mut carry = (t[0] as u128 + q as u128 * m[0] as u128) >> 64;
            for j in 1..n {
                let cur = t[j] as u128 + q as u128 * m[j] as u128 + carry;
                t[j - 1] = cur as u64;
                carry = cur >> 64;
            }
            let cur = t[n] as u128 + carry;
            t[n - 1] = cur as u64;
            t[n] = t[n + 1] + (cur >> 64) as u64;
        }
        let mut r = t[..n].to_vec();
        if t[n] != 0 || cmp(&r, m) != Ordering::Less {
            sub_in_place(&mut r, m);
        }
        r
    }

    pub fn sqr(&self, a: &[u64]) -> Vec<u64> {
        self.mul(a, a)
    }

    /// Converts a reduced value (< m, length n) into Montgomery form.
    pub fn to_mont(&self, a: &[u64]) -> Vec<u64> {
        self.mul(a, &self.r2)
    }

    pub fn from_mont(&self, a: &[u64]) -> Vec<u64> {
        let mut one = vec![0u64; self.n];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// base^exp where `base` is in Montgomery form; the result is in Montgomery form.
    pub fn pow(&self, base: &[u64], exp: &[u64]) -> Vec<u64> {
        let mut result = self.one();
        let bits = bit_len(exp);
        for i in (0..bits).rev() {
            result = self.sqr(&result);
            if bit(exp, i) {
                result = self.mul(&result, base);
            }
        }
        result
    }

    /// Modular inverse for a PRIME modulus via Fermat's little theorem.
    /// Input and output are in Montgomery form.
    #[allow(dead_code)] // only the tests use it
    pub fn inv(&self, a: &[u64]) -> Vec<u64> {
        let mut e = self.m.clone();
        // e = m - 2
        let mut two = vec![0u64; self.n];
        two[0] = 2;
        sub_in_place(&mut e, &two);
        self.pow(a, &e)
    }
}

/// Fixed-size Montgomery arithmetic: values are `[u64; N]` with N a const generic, so the loops unroll and nothing is
/// allocated. ECDSA verification (N = 4, 6 and 9) and RSA verification (N = 16 to 64) use it; [`Mont`] is the general case.
pub(crate) mod fixed {
    use std::cmp::Ordering;

    /// A number below a modulus of N limbs, least significant limb first.
    pub(crate) type Fe<const N: usize> = [u64; N];

    pub(crate) fn is_zero<const N: usize>(a: &Fe<N>) -> bool {
        a.iter().all(|&x| x == 0)
    }

    pub(crate) fn compare<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> Ordering {
        for i in (0..N).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        Ordering::Equal
    }

    /// a + b, and whether it carried out of the top limb.
    #[inline(always)]
    pub(crate) fn add_carry<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> (Fe<N>, bool) {
        let mut r = [0u64; N];
        let mut carry = 0u64;
        for i in 0..N {
            let s = a[i] as u128 + b[i] as u128 + carry as u128;
            r[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        (r, carry != 0)
    }

    /// a - b, and whether it borrowed from beyond the top limb.
    #[inline(always)]
    pub(crate) fn sub_borrow<const N: usize>(a: &Fe<N>, b: &Fe<N>) -> (Fe<N>, bool) {
        let mut r = [0u64; N];
        let mut borrow = 0u64;
        for i in 0..N {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r[i] = d2;
            borrow = (b1 | b2) as u64;
        }
        (r, borrow != 0)
    }

    /// Big-endian bytes (at most 8 * N of them) as limbs.
    pub(crate) fn limbs_from_be<const N: usize>(bytes: &[u8]) -> Option<Fe<N>> {
        if bytes.len() > 8 * N {
            return None;
        }
        let mut r = [0u64; N];
        for (i, b) in bytes.iter().rev().enumerate() {
            r[i / 8] |= (*b as u64) << (8 * (i % 8));
        }
        Some(r)
    }

    pub(crate) fn limbs_from_hex<const N: usize>(hex: &str) -> Fe<N> {
        limbs_from_be(&crate::util::unhex(hex)).expect("constant fits")
    }

    /// The prime of P-256, 2^256 - 2^224 + 2^192 + 2^96 - 1, whose limbs make Montgomery reduction cheap: -p^-1 mod 2^64 is 1,
    /// the low limb is 2^64 - 1, the next 2^32 - 1, the third 0.
    const P256: [u64; 4] = [u64::MAX, 0x0000_0000_ffff_ffff, 0, 0xffff_ffff_0000_0001];

    /// From this many limbs (RSA-2048 and up) products and squares are made a column of the result at a time (product
    /// scanning) and squares make each product of two different limbs once; below, at the curves' sizes and RSA-1024 and
    /// -1536, a row at a time (CIOS), squares being products. Measured (B-103): from 32 limbs up the columns take about 0.55
    /// times as long as the rows on an Apple M5 and 0.85 times on an x86-64 server; at 16 and 24 limbs up to 1.3 times as
    /// long on the x86-64; at the curves' sizes a separate square gained nothing that could be told from noise (B-49).
    const COLUMNS_MIN: usize = 32;

    /// Arithmetic modulo an odd number of N limbs (the top one not zero), in Montgomery form (R = 2^(64 N)), on values below
    /// it. Variable time: for public values only (signature verification).
    pub(crate) struct Field<const N: usize> {
        pub(crate) m: Fe<N>,
        /// -m^-1 mod 2^64
        m0inv: u64,
        /// R mod m: the Montgomery form of 1
        pub(crate) one: Fe<N>,
        /// R^2 mod m
        r2: Fe<N>,
        /// m is P-256's prime (see [`P256`])
        p256: bool,
    }

    impl<const N: usize> Field<N> {
        pub(crate) fn new(modulus_hex: &str) -> Field<N> {
            Field::from_modulus(limbs_from_hex(modulus_hex))
        }

        /// For an odd modulus whose top limb is not zero.
        pub(crate) fn from_modulus(m: Fe<N>) -> Field<N> {
            assert!(m[0] & 1 == 1 && m[N - 1] != 0, "an odd modulus of N limbs");
            // -m^-1 mod 2^64 by Newton's iteration (each step doubles the bits that are right)
            let mut inv = 1u64;
            for _ in 0..6 {
                inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            }
            let p256 = N == 4 && m[..] == P256[..];
            let mut f = Field { m, m0inv: inv.wrapping_neg(), one: [0; N], r2: [0; N], p256 };
            // R mod m: the highest power of two below m, doubled up to 2^(64 N) (at most 64 doublings: the top limb is not 0)
            let bits = 64 * N - m[N - 1].leading_zeros() as usize;
            let mut x = [0u64; N];
            x[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
            for _ in 0..64 * N - (bits - 1) {
                x = f.add(&x, &x);
            }
            f.one = x;
            // R^2 mod m = R (R mod m) mod m, by long division: a few times quicker than doublings and squares (B-103)
            f.r2 = shift_mod(&m, &f.one);
            f
        }

        /// `t` (with the carry out of its top limb) reduced once: minus m if it is at least m.
        #[inline(always)]
        pub(crate) fn reduce_once(&self, t: Fe<N>, carry: bool) -> Fe<N> {
            let (d, borrow) = sub_borrow(&t, &self.m);
            if carry || !borrow {
                d
            } else {
                t
            }
        }

        #[inline(always)]
        pub(crate) fn add(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            let (s, carry) = add_carry(a, b);
            self.reduce_once(s, carry)
        }

        #[inline(always)]
        pub(crate) fn sub(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            let (d, borrow) = sub_borrow(a, b);
            if borrow {
                add_carry(&d, &self.m).0
            } else {
                d
            }
        }

        /// m - a (0 for 0).
        #[inline(always)]
        pub(crate) fn neg(&self, a: &Fe<N>) -> Fe<N> {
            if is_zero(a) {
                *a
            } else {
                sub_borrow(&self.m, a).0
            }
        }

        /// The Montgomery product a * b / R mod m, for a and b below m.
        #[inline(always)]
        pub(crate) fn mul(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            if N >= COLUMNS_MIN {
                self.mul_columns(a, b)
            } else {
                self.mul_rows(a, b)
            }
        }

        /// a * a / R mod m.
        #[inline(always)]
        pub(crate) fn sqr(&self, a: &Fe<N>) -> Fe<N> {
            if N >= COLUMNS_MIN {
                self.sqr_columns(a)
            } else {
                self.mul_rows(a, a)
            }
        }

        /// The Montgomery product by rows (CIOS): each limb of b times a, added, then the multiple of m that clears the lowest
        /// limb, shifted out.
        #[inline(always)]
        pub(super) fn mul_rows(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            if N == 4 && self.p256 {
                let mut r = [0u64; N];
                r[..4].copy_from_slice(&mul_p256(a[..4].try_into().unwrap(), b[..4].try_into().unwrap()));
                return r;
            }
            let mut t = [0u64; N];
            let mut tn = 0u64; // the limb above t
            for i in 0..N {
                let bi = b[i] as u128;
                let mut c = 0u128;
                for j in 0..N {
                    let s = t[j] as u128 + a[j] as u128 * bi + c;
                    t[j] = s as u64;
                    c = s >> 64;
                }
                let s = tn as u128 + c;
                tn = s as u64;
                let tn1 = (s >> 64) as u64; // the limb above that

                let q = t[0].wrapping_mul(self.m0inv) as u128;
                let s = t[0] as u128 + q * self.m[0] as u128;
                let mut c = s >> 64;
                for j in 1..N {
                    let s = t[j] as u128 + q * self.m[j] as u128 + c;
                    t[j - 1] = s as u64;
                    c = s >> 64;
                }
                let s = tn as u128 + c;
                t[N - 1] = s as u64;
                tn = tn1 + (s >> 64) as u64;
            }
            self.reduce_once(t, tn != 0)
        }

        /// The Montgomery product by columns (product scanning, with the reduction interleaved): column i of the sum
        /// a b + q m, q being chosen limb by limb as the column is reached so that the limbs below N are zero, is added into
        /// a three-limb accumulator; the columns from N up are the result (below 2m), reduced once.
        #[inline(always)]
        pub(super) fn mul_columns(&self, a: &Fe<N>, b: &Fe<N>) -> Fe<N> {
            let mut q = [0u64; N];
            let mut r = [0u64; N];
            let mut acc = Column::default();
            for i in 0..N {
                for j in 0..i {
                    acc.add_product(a[j], b[i - j]);
                    acc.add_product(q[j], self.m[i - j]);
                }
                acc.add_product(a[i], b[0]);
                q[i] = acc.low().wrapping_mul(self.m0inv);
                acc.add_product(q[i], self.m[0]);
                acc.shift(); // zero, by the choice of q[i]
            }
            for i in N..2 * N {
                for j in i + 1 - N..N {
                    acc.add_product(a[j], b[i - j]);
                    acc.add_product(q[j], self.m[i - j]);
                }
                r[i - N] = acc.shift();
            }
            self.reduce_once(r, !acc.is_zero())
        }

        /// The square by columns, as [`Field::mul_columns`], each product of two different limbs made once and doubled
        /// (N (N + 1) / 2 products of a where a product makes N^2).
        #[inline(always)]
        pub(super) fn sqr_columns(&self, a: &Fe<N>) -> Fe<N> {
            let mut q = [0u64; N];
            let mut r = [0u64; N];
            let mut acc = Column::default();
            for i in 0..2 * N {
                // the limbs of a that meet in column i: j and i - j, both below N
                let first = (i + 1).saturating_sub(N);
                let mut cross = Column::default();
                for j in first..(i + 1) / 2 {
                    cross.add_product(a[j], a[i - j]);
                }
                acc.add(&cross);
                acc.add(&cross);
                if i % 2 == 0 {
                    acc.add_product(a[i / 2], a[i / 2]);
                }
                if i < N {
                    for j in 0..i {
                        acc.add_product(q[j], self.m[i - j]);
                    }
                    q[i] = acc.low().wrapping_mul(self.m0inv);
                    acc.add_product(q[i], self.m[0]);
                    acc.shift(); // zero
                } else {
                    for j in first..N {
                        acc.add_product(q[j], self.m[i - j]);
                    }
                    r[i - N] = acc.shift();
                }
            }
            self.reduce_once(r, !acc.is_zero())
        }

        pub(crate) fn to_mont(&self, a: &Fe<N>) -> Fe<N> {
            self.mul(a, &self.r2)
        }

        #[cfg(test)]
        pub(crate) fn from_mont(&self, a: &Fe<N>) -> Fe<N> {
            let mut one = [0u64; N];
            one[0] = 1;
            self.mul(a, &one)
        }

        #[cfg(test)]
        pub(crate) fn r2_for_tests(&self) -> Fe<N> {
            self.r2
        }

        /// Whether m is P-256's prime, which has a reduction of its own.
        #[inline(always)]
        pub(crate) fn is_p256(&self) -> bool {
            self.p256
        }

        /// base^e mod m, for `base` below m (as it is, not in Montgomery form) and an odd e of at least 3: square and multiply
        /// from the top bit, the last multiplication by `base` itself, which also takes the result out of Montgomery form
        /// ((x R) b / R = x b): one product fewer than converting at the end.
        pub(crate) fn pow_odd(&self, base: &Fe<N>, e: u64) -> Fe<N> {
            assert!(e & 1 == 1 && e >= 3, "an odd exponent of at least 3");
            let bm = self.to_mont(base);
            let mut r = bm;
            let bits = 64 - e.leading_zeros();
            for i in (1..bits - 1).rev() {
                r = self.sqr(&r);
                if (e >> i) & 1 == 1 {
                    r = self.mul(&r, &bm);
                }
            }
            r = self.sqr(&r);
            self.mul(&r, base)
        }

        /// The inverse of a nonzero value (Montgomery form in, Montgomery form out) by Fermat's little theorem:
        /// a^(m-2), in windows of four bits.
        pub(crate) fn inv(&self, a: &Fe<N>) -> Fe<N> {
            let mut e = self.m;
            e[0] -= 2; // the low limb of every modulus used here is far above 2
            let mut table = [self.one; 16];
            table[1] = *a;
            for i in 2..16 {
                table[i] = self.mul(&table[i - 1], a);
            }
            let mut r = self.one;
            for limb in (0..N).rev() {
                for nibble in (0..16).rev() {
                    for _ in 0..4 {
                        r = self.sqr(&r);
                    }
                    let d = ((e[limb] >> (4 * nibble)) & 15) as usize;
                    if d != 0 {
                        r = self.mul(&r, &table[d]);
                    }
                }
            }
            r
        }

        /// The inverse of a nonzero value below m, for a prime m, by the binary extended Euclidean algorithm: plain
        /// numbers in and out (not Montgomery form). Its steps depend on the value, so it is for public values only (an
        /// ECDSA signature's s); about twice as quick as [`Field::inv`]'s exponentiation for P-256 (4 against 8 us on an x86-64 server, B-104).
        pub(crate) fn inv_vartime(&self, a: &Fe<N>) -> Fe<N> {
            let mut one = [0u64; N];
            one[0] = 1;
            // x1 a = u and x2 a = v (mod m) throughout; u and v come down to their gcd, 1
            let (mut u, mut v) = (*a, self.m);
            let (mut x1, mut x2) = (one, [0u64; N]);
            while u != one && v != one {
                if is_zero(&u) || is_zero(&v) {
                    return [0; N]; // not invertible: m is not prime, or a is a multiple of it
                }
                while u[0] & 1 == 0 {
                    shift_right_one(&mut u, false);
                    self.halve(&mut x1);
                }
                while v[0] & 1 == 0 {
                    shift_right_one(&mut v, false);
                    self.halve(&mut x2);
                }
                if compare(&u, &v) != Ordering::Less {
                    u = sub_borrow(&u, &v).0;
                    x1 = self.sub(&x1, &x2);
                } else {
                    v = sub_borrow(&v, &u).0;
                    x2 = self.sub(&x2, &x1);
                }
            }
            if u == one {
                x1
            } else {
                x2
            }
        }

        /// x / 2 mod m, for x below m: x shifted if it is even, x + m shifted (with its carry as the new top bit) if not.
        #[inline(always)]
        fn halve(&self, x: &mut Fe<N>) {
            let carry = if x[0] & 1 == 1 {
                let (sum, carry) = add_carry(x, &self.m);
                *x = sum;
                carry
            } else {
                false
            };
            shift_right_one(x, carry);
        }
    }

    /// x >> 1, with `top` as the new top bit.
    #[inline(always)]
    fn shift_right_one<const N: usize>(x: &mut Fe<N>, top: bool) {
        for i in 0..N {
            let above = if i + 1 < N { x[i + 1] } else { top as u64 };
            x[i] = (x[i] >> 1) | (above << 63);
        }
    }

    /// A column sum of products: 192 bits (the low 128, and the limb above). A column has at most 2N + 2 products of two
    /// limbs and what the column below carried, so it fits for any N a modulus could have.
    #[derive(Default)]
    struct Column {
        low: u128,
        high: u64,
    }

    impl Column {
        #[inline(always)]
        fn add_product(&mut self, x: u64, y: u64) {
            let (s, c) = self.low.overflowing_add(x as u128 * y as u128);
            self.low = s;
            self.high += c as u64;
        }

        #[inline(always)]
        fn add(&mut self, other: &Column) {
            let (s, c) = self.low.overflowing_add(other.low);
            self.low = s;
            self.high += other.high + c as u64;
        }

        #[inline(always)]
        fn low(&self) -> u64 {
            self.low as u64
        }

        /// The lowest limb, taken out (the sum moves down a limb, which carries it into the next column).
        #[inline(always)]
        fn shift(&mut self) -> u64 {
            let out = self.low as u64;
            self.low = (self.low >> 64) | ((self.high as u128) << 64);
            self.high = 0;
            out
        }

        #[inline(always)]
        fn is_zero(&self) -> bool {
            self.low == 0 && self.high == 0
        }
    }

    /// (x 2^(64 N)) mod m, for x below m and m odd with its top limb not zero, by long division (Knuth's algorithm D, the
    /// remainder only). For the constants: R mod m from 1, R^2 mod m from R mod m.
    pub(super) fn shift_mod<const N: usize>(m: &Fe<N>, x: &Fe<N>) -> Fe<N> {
        // Normalized: v = m and u = x 2^(64 N) shifted left until v's top bit is set (u then has 2N + 1 limbs).
        let d = m[N - 1].leading_zeros();
        let shift_left = |from: &[u64], to: &mut [u64]| -> u64 {
            let mut carry = 0u64;
            for (t, &f) in to.iter_mut().zip(from) {
                *t = if d == 0 { f } else { (f << d) | carry };
                carry = if d == 0 { 0 } else { f >> (64 - d) };
            }
            carry
        };
        let mut v = [0u64; N];
        shift_left(m, &mut v);
        let mut u = vec![0u64; 2 * N + 1];
        u[2 * N] = shift_left(x, &mut u[N..2 * N]);
        let v1 = v[N - 1] as u128;
        let v2 = if N >= 2 { v[N - 2] as u128 } else { 0 };
        for j in (0..N).rev() {
            // the quotient's limb j, estimated from the top two limbs over v's top limb (u[j + N] is at most v's top limb,
            // as what is left is below v), corrected by v's next limb: then too large by at most 1
            let (u0, u1) = (u[j + N], u[j + N - 1]);
            let (mut qhat, mut rhat) = if u0 as u128 == v1 {
                (u64::MAX as u128, u1 as u128 + v1)
            } else {
                let num = (u0 as u128) << 64 | u1 as u128;
                (num / v1, num % v1)
            };
            if N >= 2 {
                while rhat >> 64 == 0 && qhat * v2 > (rhat << 64 | u[j + N - 2] as u128) {
                    qhat -= 1;
                    rhat += v1;
                }
            }
            // u[j..=j + N] -= qhat v, and v added back if that went below zero
            let qhat = qhat as u64;
            let mut carry = 0u64;
            let mut borrow = false;
            for i in 0..N {
                let p = qhat as u128 * v[i] as u128 + carry as u128;
                carry = (p >> 64) as u64;
                let (d1, b1) = u[j + i].overflowing_sub(p as u64);
                let (d2, b2) = d1.overflowing_sub(borrow as u64);
                u[j + i] = d2;
                borrow = b1 | b2;
            }
            let (d1, b1) = u[j + N].overflowing_sub(carry);
            let (d2, b2) = d1.overflowing_sub(borrow as u64);
            u[j + N] = d2;
            if b1 | b2 {
                let mut carry = false;
                for i in 0..N {
                    let (s1, c1) = u[j + i].overflowing_add(v[i]);
                    let (s2, c2) = s1.overflowing_add(carry as u64);
                    u[j + i] = s2;
                    carry = c1 | c2;
                }
                u[j + N] = u[j + N].wrapping_add(carry as u64);
            }
        }
        // the remainder, below v, in u's low N limbs: shifted back
        let mut r = [0u64; N];
        for i in 0..N {
            r[i] = if d == 0 { u[i] } else { (u[i] >> d) | (u[i + 1] << (64 - d)) };
        }
        r
    }

    /// The Montgomery product modulo P-256's prime (CIOS, as [`Field::mul_rows`], with each step's reduction one product and
    /// a shift).
    #[inline(always)]
    fn mul_p256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut t = [0u64; 4];
        let mut tn = 0u64; // the limb above t
        for &bi in &b {
            let mut c = 0u128;
            for j in 0..4 {
                let s = t[j] as u128 + a[j] as u128 * bi as u128 + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = tn as u128 + c;
            tn = s as u64;
            let tn1 = (s >> 64) as u64;
            // t + q p with q = t[0], shifted down a limb
            let q = t[0];
            let s = t[1] as u128 + ((q as u128) << 32);
            let t0 = s as u64;
            let s = t[2] as u128 + (s >> 64);
            let t1 = s as u64;
            let s = t[3] as u128 + q as u128 * P256[3] as u128 + (s >> 64);
            let t2 = s as u64;
            let s = tn as u128 + (s >> 64);
            t = [t0, t1, t2, s as u64];
            tn = tn1 + (s >> 64) as u64;
        }
        let (d, borrow) = sub_borrow(&t, &P256);
        if tn != 0 || !borrow {
            d
        } else {
            t
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_roundtrip() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
        let l = from_be_bytes(&bytes);
        assert_eq!(l, vec![0x030405060708090a_u64, 0x0102]);
        assert_eq!(to_be_bytes(&l, 10), bytes.to_vec());
        assert_eq!(to_be_bytes(&l, 12)[..2], [0, 0]);
    }

    #[test]
    fn modpow_small() {
        // 4^13 mod 497 = 445 (classic example)
        let m = Mont::new(&[497]);
        let base = m.to_mont(&[4]);
        let r = m.from_mont(&m.pow(&base, &[13]));
        assert_eq!(r, vec![445]);
    }

    #[test]
    fn fermat_inverse_multi_limb() {
        // p = 2^127 - 1 (prime); check a * a^-1 == 1
        let p = from_hex("7fffffffffffffffffffffffffffffff");
        let m = Mont::new(&p);
        let a = m.to_mont(&m.fit(&from_hex("123456789abcdef0fedcba9876543210")));
        let inv = m.inv(&a);
        let one = m.from_mont(&m.mul(&a, &inv));
        assert_eq!(one, vec![1, 0]);
    }

    #[test]
    fn add_sub_wrap() {
        let m = Mont::new(&[97]);
        assert_eq!(m.add(&[90], &[20]), vec![13]);
        assert_eq!(m.sub(&[5], &[10]), vec![92]);
    }

    #[test]
    fn matches_python_modpow() {
        // pow(0xdeadbeefcafebabe1234567890abcdef, 65537, 2^192 - 237) computed with Python
        let modulus = from_hex("ffffffffffffffffffffffffffffffffffffffffffffff13");
        let m = Mont::new(&modulus);
        let base = m.to_mont(&m.fit(&from_hex("deadbeefcafebabe1234567890abcdef")));
        let r = m.from_mont(&m.pow(&base, &[65537]));
        assert_eq!(to_be_bytes(&r, 24), crate::util::unhex(PYTHON_RESULT));
    }

    /// The constants of the context against the definition (64n modular doublings of 1, then 64n more), for moduli of
    /// every size the library uses and some it does not, with top limbs from 1 to all ones.
    #[test]
    fn the_constants_are_r_and_r_squared_mod_m() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 32, 33, 47, 48, 64, 65] {
            for top in [1u64, 3, 0x1ff, 0x8000_0000_0000_0000, u64::MAX, 0] {
                let mut m: Vec<u64> = (0..n).map(|_| next()).collect();
                if top != 0 {
                    m[n - 1] = top;
                }
                m[0] |= 1;
                if n == 1 && m[0] == 1 {
                    continue;
                }
                let ctx = Mont::new(&m);
                let mut x = vec![0u64; n];
                x[0] = 1;
                for _ in 0..64 * n {
                    x = ctx.add(&x, &x);
                }
                assert_eq!(ctx.one, x, "R mod m, {n} limbs, top {top:#x}");
                for _ in 0..64 * n {
                    x = ctx.add(&x, &x);
                }
                assert_eq!(ctx.r2, x, "R^2 mod m, {n} limbs, top {top:#x}");
                // and so a round trip through the Montgomery form is the identity
                let a = ctx.fit(&[next() % m[0].max(2)]);
                assert_eq!(ctx.from_mont(&ctx.to_mont(&a)), a);
            }
        }
        let one = Mont::new(&[1]);
        assert_eq!((one.one(), one.r2.clone()), (vec![0], vec![0]));
    }

    const PYTHON_RESULT: &str = "04b8399e2761eeefd31b998f36722aa31e7c257d126c1760";

    /// The two ways of multiplying (by columns from 32 limbs up, by rows below) give the same products and squares at every
    /// size, on random values and at the edges, for moduli with top limbs of 1, of all ones and random.
    #[test]
    fn the_columns_agree_with_the_rows() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        fn check<const N: usize>(m: [u64; N], next: &mut impl FnMut() -> u64) {
            let f = fixed::Field::<N>::from_modulus(m);
            let mut m_minus_1 = m;
            m_minus_1[0] -= 1;
            let mut one = [0u64; N];
            one[0] = 1;
            let mut high = [u64::MAX; N];
            high[N - 1] = m[N - 1] - 1;
            let mut values = vec![[0u64; N], one, m_minus_1];
            if m[N - 1] > 1 {
                values.push(high);
            }
            for _ in 0..12 {
                let mut a: [u64; N] = core::array::from_fn(|_| next());
                a[N - 1] %= m[N - 1];
                values.push(a);
            }
            for a in &values {
                assert_eq!(f.sqr_columns(a), f.mul_rows(a, a), "square, {N} limbs");
                for b in &values {
                    assert_eq!(f.mul_columns(a, b), f.mul_rows(a, b), "product, {N} limbs");
                }
            }
        }
        macro_rules! sizes {
            ($($n:literal),*) => {$(
                for top in [1u64, u64::MAX, 0] {
                    let mut m: [u64; $n] = core::array::from_fn(|_| next());
                    if top != 0 {
                        m[$n - 1] = top;
                    }
                    if m[$n - 1] == 0 {
                        m[$n - 1] = 1;
                    }
                    m[0] |= 1;
                    if $n == 1 && m[0] == 1 {
                        m[0] = 3;
                    }
                    check::<$n>(m, &mut next);
                }
            )*};
        }
        sizes!(1, 2, 4, 9, 16, 31, 32, 33, 48, 64);
    }

    /// The binary inversion (ECDSA's, for public values) gives what Fermat's exponentiation gives, modulo the primes and
    /// group orders of P-256, P-384 and P-521, at 1, 2, m - 1, m - 2 and random values; and a times it is 1.
    #[test]
    fn the_binary_inversion_agrees_with_fermats() {
        let mut seed = 0x0f1e_2d3c_4b5a_6978u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        fn check<const N: usize>(hex: &str, next: &mut impl FnMut() -> u64) {
            let f = fixed::Field::<N>::new(hex);
            let m = f.m;
            let mut values = Vec::new();
            for k in [1u64, 2] {
                let mut a = [0u64; N];
                a[0] = k;
                values.push(a);
                let mut b = m;
                b[0] -= k;
                values.push(b);
            }
            for _ in 0..200 {
                let mut a: [u64; N] = core::array::from_fn(|_| next());
                a[N - 1] %= m[N - 1];
                if fixed::is_zero(&a) {
                    continue;
                }
                values.push(a);
            }
            let mut one = [0u64; N];
            one[0] = 1;
            for a in &values {
                let inv = f.inv_vartime(a);
                assert_eq!(inv, f.from_mont(&f.inv(&f.to_mont(a))), "{N} limbs, a {a:x?}");
                assert_eq!(f.mul(&f.to_mont(a), &inv), one, "a times its inverse, {N} limbs");
            }
        }
        check::<4>("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", &mut next);
        check::<4>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", &mut next);
        check::<6>("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", &mut next);
        check::<6>("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", &mut next);
        check::<9>("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut next);
        check::<9>("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", &mut next);
    }

    /// The long division that makes R^2 mod m gives x R mod m as the general code does: on random moduli and values, at the
    /// edges, and on the inputs that take its two rare paths (the estimate of a quotient limb one too large after its
    /// correction, so that v is added back; the top limb left equal to v's).
    #[test]
    fn long_division_agrees_with_the_general_code() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        fn check<const N: usize>(m: [u64; N], extra: &[[u64; N]], next: &mut impl FnMut() -> u64) {
            let g = Mont::new(&m);
            let mut m_minus_1 = m;
            m_minus_1[0] -= 1;
            let mut one = [0u64; N];
            one[0] = 1;
            let mut values = vec![[0u64; N], one, m_minus_1];
            values.extend_from_slice(extra);
            for _ in 0..20 {
                let mut a: [u64; N] = core::array::from_fn(|_| next());
                a[N - 1] %= m[N - 1];
                values.push(a);
            }
            for x in &values {
                assert_eq!(fixed::shift_mod(&m, x).to_vec(), g.to_mont(x), "{N} limbs, m {m:x?}, x {x:x?}");
            }
        }
        // the rare paths: m = 2^191 + 2^64 - 1 is normalized, and for x = 2^128 (or 2^128 + 1) the first quotient limb is
        // estimated as 2 from the top two limbs, v's next limb (0) does not correct it, and 2m is above x 2^192's top part
        check::<3>([u64::MAX, 0, 1 << 63], &[[0, 0, 1], [1, 0, 1]], &mut next);
        // m = 2^127 + 1, x = m - 1: the top limb of what is divided equals v's
        check::<2>([1, 1 << 63], &[], &mut next);
        macro_rules! sizes {
            ($($n:literal),*) => {$(
                for top in [1u64, 2, 1 << 63, u64::MAX, 0] {
                    let mut m: [u64; $n] = core::array::from_fn(|_| next());
                    if top != 0 {
                        m[$n - 1] = top;
                    }
                    if m[$n - 1] == 0 {
                        m[$n - 1] = 1;
                    }
                    m[0] |= 1;
                    if $n == 1 && m[0] == 1 {
                        m[0] = 3;
                    }
                    check::<$n>(m, &[], &mut next);
                }
            )*};
        }
        sizes!(1, 2, 3, 4, 6, 9, 16, 32, 64);
    }

    /// The fixed-size arithmetic agrees with the general code: the constants, products, squares (the dedicated squaring
    /// at RSA's sizes) and odd powers, on random moduli of every size the library uses, with top limbs of 1 and all ones,
    /// on random values and at the edges (0, 1, m - 1); and P-256's own reduction agrees with the general one.
    #[test]
    fn fixed_size_arithmetic_matches_the_general_code() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        fn check<const N: usize>(m: [u64; N], next: &mut impl FnMut() -> u64) {
            let f = fixed::Field::<N>::from_modulus(m);
            let g = Mont::new(&m);
            assert_eq!((f.one.to_vec(), f.r2_for_tests().to_vec()), (g.one.clone(), g.r2.clone()), "constants, {N} limbs");
            let below = |next: &mut dyn FnMut() -> u64| -> [u64; N] {
                let mut a: [u64; N] = core::array::from_fn(|_| next());
                a[N - 1] %= m[N - 1]; // under m's top limb, so under m
                a
            };
            let mut m_minus_1 = m;
            m_minus_1[0] -= 1;
            let mut one = [0u64; N];
            one[0] = 1;
            let mut values = vec![[0u64; N], one, m_minus_1];
            for _ in 0..6 {
                values.push(below(next));
            }
            for a in &values {
                assert_eq!(f.sqr(a).to_vec(), g.mul(a, a), "square, {N} limbs");
                for b in &values {
                    assert_eq!(f.mul(a, b).to_vec(), g.mul(a, b), "product, {N} limbs");
                }
                for e in [3u64, 65537, next() | 1 | (1 << 63)] {
                    assert_eq!(f.pow_odd(a, e).to_vec(), g.from_mont(&g.pow(&g.to_mont(a), &[e])), "power {e}, {N} limbs");
                }
            }
        }
        macro_rules! sizes {
            ($($n:literal),*) => {$(
                for top in [1u64, u64::MAX, 0] {
                    let mut m: [u64; $n] = core::array::from_fn(|_| next());
                    m[0] |= 1;
                    if top != 0 {
                        m[$n - 1] = top;
                    }
                    if m[$n - 1] == 0 {
                        m[$n - 1] = 1;
                    }
                    check::<$n>(m, &mut next);
                }
            )*};
        }
        sizes!(4, 6, 9, 16, 17, 24, 32, 48, 64);
        // P-256's prime takes its own reduction
        let p256: [u64; 4] = fixed::limbs_from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        check::<4>(p256, &mut next);
        assert!(fixed::Field::<4>::from_modulus(p256).is_p256());
    }
}

