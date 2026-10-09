//! Arithmetic in the field of 2^255 - 19, in 5 x 51-bit limbs.
//!
//! This is the field underneath both X25519 (`x25519.rs`, which needs it to be constant time) and
//! Ed25519 verification (`ed25519.rs`, which only handles public data). Every operation here is
//! branch-free on the limbs; the only branches are on public exponents (`invert`, `pow22523`) and in
//! the comparisons that callers make on public values (`equals`, `is_negative`).
//!
//! A value is any 5-limb array whose limbs are below 2^51 plus a small slack; the representation is
//! not unique, so equality goes through `to_bytes`, which is canonical.

pub(crate) const MASK51: u64 = (1 << 51) - 1;

#[derive(Clone, Copy)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

#[inline]
fn load8(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// a * b as one 64 x 64 -> 128-bit product.
#[inline(always)]
fn m(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// The curve constant d = -121665/121666 of edwards25519.
    pub(crate) const D: Fe = Fe([0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029, 0x739c663a03cbb, 0x52036cee2b6ff]);
    /// 2d.
    pub(crate) const D2: Fe = Fe([0x69b9426b2f159, 0x35050762add7a, 0x3cf44c0038052, 0x6738cc7407977, 0x2406d9dc56dff]);
    /// A square root of -1: 2^((p-1)/4).
    pub(crate) const SQRT_M1: Fe = Fe([0x61b274a0ea0b0, 0x0d5a5fc8f189d, 0x7ef5e9cbd0c60, 0x78595a6804c9e, 0x2b8324804fc1d]);
    /// The x and y coordinates of the edwards25519 base point.
    pub(crate) const BASE_X: Fe = Fe([0x62d608f25d51a, 0x412a4b4f6592a, 0x75b7171a4b31d, 0x1ff60527118fe, 0x216936d3cd6e5]);
    pub(crate) const BASE_Y: Fe = Fe([0x6666666666658, 0x4cccccccccccc, 0x1999999999999, 0x3333333333333, 0x6666666666666]);

    /// Loads 255 bits, little endian. The top bit of the last byte is ignored, and a value of p or
    /// more is accepted and taken modulo p (so this is not a canonical decoder).
    pub(crate) fn from_bytes(s: &[u8; 32]) -> Fe {
        Fe([
            load8(&s[0..8]) & MASK51,
            (load8(&s[6..14]) >> 3) & MASK51,
            (load8(&s[12..20]) >> 6) & MASK51,
            (load8(&s[19..27]) >> 1) & MASK51,
            (load8(&s[24..32]) >> 12) & MASK51,
        ])
    }

    /// Weak reduction: every limb < 2^51 + small.
    #[inline(always)]
    pub(crate) fn carry(self) -> Fe {
        let mut h = self.0;
        let c0 = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c0;
        let c1 = h[1] >> 51;
        h[1] &= MASK51;
        h[2] += c1;
        let c2 = h[2] >> 51;
        h[2] &= MASK51;
        h[3] += c2;
        let c3 = h[3] >> 51;
        h[3] &= MASK51;
        h[4] += c3;
        let c4 = h[4] >> 51;
        h[4] &= MASK51;
        h[0] += c4 * 19;
        let c = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c;
        Fe(h)
    }

    #[inline(always)]
    pub(crate) fn add(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        Fe([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]]).carry()
    }

    #[inline(always)]
    pub(crate) fn sub(self, o: Fe) -> Fe {
        // add 2p before subtracting so limbs never underflow
        const TWO_P0: u64 = 0xfffffffffffda;
        const TWO_PN: u64 = 0xffffffffffffe;
        let a = self.0;
        let b = o.0;
        Fe([
            a[0] + TWO_P0 - b[0],
            a[1] + TWO_PN - b[1],
            a[2] + TWO_PN - b[2],
            a[3] + TWO_PN - b[3],
            a[4] + TWO_PN - b[4],
        ])
        .carry()
    }

    /// `self + o` without the carry pass, for a result that only goes into `mul`, `square` or `sub_lazy`'s
    /// operands' place in a product. Both operands must have limbs below 2^52 (any output of `mul`, `square`,
    /// `carry`, `add` or `sub`); the sum's limbs are then below 2^53, which `mul` and `square` take (their products
    /// stay below 2^112). The X25519 ladder uses it (B-103).
    #[allow(dead_code)] // used by x25519.rs (the `net` part)
    #[inline(always)]
    pub(crate) fn add_lazy(self, o: Fe) -> Fe {
        let (a, b) = (self.0, o.0);
        Fe([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    /// `self - o` without the carry pass: `self + 2p - o`, limb by limb, which cannot underflow when `o`'s limbs are
    /// below 2^51 + 2^12 (any output of `mul`, `square` or `carry`). The result's limbs are below 2^53, for `mul`,
    /// `square` or `mul_small`. The X25519 ladder uses it (B-103).
    #[allow(dead_code)] // used by x25519.rs (the `net` part)
    #[inline(always)]
    pub(crate) fn sub_lazy(self, o: Fe) -> Fe {
        const TWO_P0: u64 = 0xfffffffffffda;
        const TWO_PN: u64 = 0xffffffffffffe;
        let (a, b) = (self.0, o.0);
        Fe([a[0] + TWO_P0 - b[0], a[1] + TWO_PN - b[1], a[2] + TWO_PN - b[2], a[3] + TWO_PN - b[3], a[4] + TWO_PN - b[4]])
    }

    pub(crate) fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    #[inline(always)]
    pub(crate) fn mul(self, o: Fe) -> Fe {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = o.0;
        // the multiples by 19 in 64 bits (limbs below 2^53 make them below 2^58), so that every product below is one
        // 64 x 64 -> 128-bit multiplication: made in 128 bits, the compiler cannot tell they fit, and multiplies
        // 128 by 128 bits (three instructions for one, 38 for the 25 products; B-104)
        let (b1_19, b2_19, b3_19, b4_19) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
        let c0 = m(a0, b0) + m(a1, b4_19) + m(a2, b3_19) + m(a3, b2_19) + m(a4, b1_19);
        let c1 = m(a0, b1) + m(a1, b0) + m(a2, b4_19) + m(a3, b3_19) + m(a4, b2_19);
        let c2 = m(a0, b2) + m(a1, b1) + m(a2, b0) + m(a3, b4_19) + m(a4, b3_19);
        let c3 = m(a0, b3) + m(a1, b2) + m(a2, b1) + m(a3, b0) + m(a4, b4_19);
        let c4 = m(a0, b4) + m(a1, b3) + m(a2, b2) + m(a3, b1) + m(a4, b0);
        Fe::reduce([c0, c1, c2, c3, c4])
    }

    /// self * self, with 15 products instead of 25 (each cross product once, doubled).
    #[inline(always)]
    pub(crate) fn square(self) -> Fe {
        let [a0, a1, a2, a3, a4] = self.0;
        // the doubles and multiples by 19 in 64 bits, as in `mul`
        let (a3_19, a4_19) = (a3 * 19, a4 * 19);
        let (d0, d1, d2, d3) = (a0 * 2, a1 * 2, a2 * 2, a3 * 2);
        let c0 = m(a0, a0) + m(d1, a4_19) + m(d2, a3_19);
        let c1 = m(d0, a1) + m(d2, a4_19) + m(a3, a3_19);
        let c2 = m(d0, a2) + m(a1, a1) + m(d3, a4_19);
        let c3 = m(d0, a3) + m(d1, a2) + m(a4, a4_19);
        let c4 = m(d0, a4) + m(d1, a3) + m(a2, a2);
        Fe::reduce([c0, c1, c2, c3, c4])
    }

    /// The five column sums of a product (each below 2^115) carried into limbs: below 2^51, but for the second,
    /// which may exceed it by a few bits (the representation's slack).
    #[inline(always)]
    fn reduce(c: [u128; 5]) -> Fe {
        let [c0, mut c1, mut c2, mut c3, mut c4] = c;
        c1 += c0 >> 51;
        let r0 = c0 as u64 & MASK51;
        c2 += c1 >> 51;
        let r1 = c1 as u64 & MASK51;
        c3 += c2 >> 51;
        let r2 = c2 as u64 & MASK51;
        c4 += c3 >> 51;
        let r3 = c3 as u64 & MASK51;
        let carry = (c4 >> 51) as u64;
        let r4 = c4 as u64 & MASK51;
        // c0..c4 were carried into limbs below 2^51 and the top carry folded into r0, which can be well over 2^51:
        // one more step moves its excess into r1, which then exceeds 2^51 by a few bits at most (the representation's
        // slack). A second full pass would change nothing that matters (B-103).
        let r0 = r0 + carry * 19;
        let r1 = r1 + (r0 >> 51);
        Fe([r0 & MASK51, r1, r2, r3, r4])
    }

    /// self squared `k` times: self^(2^k).
    fn square_times(self, k: u32) -> Fe {
        let mut r = self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// (self^(2^250 - 1), self^11): the start that the two exponents below share, by the addition chain of
    /// ref10 and curve25519-dalek (254 squarings and 11 multiplications for the inverse). The exponents are
    /// public, so the sequence of operations is the same for every input.
    fn pow22501(self) -> (Fe, Fe) {
        let t0 = self.square(); // 2
        let t1 = t0.square_times(2); // 8
        let t2 = self.mul(t1); // 9
        let t3 = t0.mul(t2); // 11
        let t4 = t3.square(); // 22
        let t5 = t2.mul(t4); // 31 = 2^5 - 1
        let t7 = t5.square_times(5).mul(t5); // 2^10 - 1
        let t9 = t7.square_times(10).mul(t7); // 2^20 - 1
        let t11 = t9.square_times(20).mul(t9); // 2^40 - 1
        let t13 = t11.square_times(10).mul(t7); // 2^50 - 1
        let t15 = t13.square_times(50).mul(t13); // 2^100 - 1
        let t17 = t15.square_times(100).mul(t15); // 2^200 - 1
        let t19 = t17.square_times(50).mul(t13); // 2^250 - 1
        (t19, t3)
    }

    /// self^(p-2) mod p, p - 2 = 2^255 - 21 = (2^250 - 1) * 2^5 + 11. The inverse of zero is zero.
    pub(crate) fn invert(self) -> Fe {
        let (t19, t3) = self.pow22501();
        t19.square_times(5).mul(t3)
    }

    /// self^((p-5)/8) mod p, (p - 5) / 8 = 2^252 - 3 = (2^250 - 1) * 4 + 1: the exponent of the square-root
    /// candidate in RFC 8032 section 5.1.3.
    pub(crate) fn pow22523(self) -> Fe {
        let (t19, _) = self.pow22501();
        t19.square_times(2).mul(self)
    }

    /// The canonical little-endian encoding, fully reduced modulo p.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut h = self.carry().carry().0;
        // compute q = 1 if h >= p, else 0
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        let c = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c;
        let c = h[1] >> 51;
        h[1] &= MASK51;
        h[2] += c;
        let c = h[2] >> 51;
        h[2] &= MASK51;
        h[3] += c;
        let c = h[3] >> 51;
        h[3] &= MASK51;
        h[4] += c;
        h[4] &= MASK51;

        let w0 = h[0] | (h[1] << 51);
        let w1 = (h[1] >> 13) | (h[2] << 38);
        let w2 = (h[2] >> 26) | (h[3] << 25);
        let w3 = (h[3] >> 39) | (h[4] << 12);
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    /// Equality as field elements (compares the canonical encodings). Not constant time: for public
    /// values only.
    pub(crate) fn equals(self, o: Fe) -> bool {
        self.to_bytes() == o.to_bytes()
    }

    /// The "sign" of RFC 8032: the low bit of the canonical encoding.
    pub(crate) fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    fn small(k: u64) -> Fe {
        Fe([k, 0, 0, 0, 0])
    }

    fn fe(s: &str) -> Fe {
        Fe::from_bytes(&unhex(s).try_into().unwrap())
    }

    /// (a, b, a*b, a+b, a-b, 1/a), all little-endian and reduced, generated with Python integers.
    /// The inputs include values at and above p (the encoding is not canonical) and 2^255 - 1.
    const TABLE: &[(&str, &str, &str, &str, &str, &str)] = &[
        ("6aad39f4c2aaed1a8a27e534ce4aa7426078fe43c27a88b4ada9dd74482b8410", "232cae48c88fff9b500f0b4cca8e9f33a72971aa44125c7294d11bb5c82df818", "4d9c89b13b70b95cd657e3834059cf68e24ce21919e03c3a40f70b9a3d6bf258", "8dd9e73c8b3aedb6da36f08098d9467607a26fee068de426427bf92911597c29", "34818babfa1aee7e3918dae803bc070fb94e8d997d682c4219d8c1bf7ffd8b77", "3eb7b9b06dbd9f24df520e8f63ba87954dd94f0fa3a043496e36afc2a4d8b36e"),
        ("52c00060c28921553a62c526134241b82b54e7a6e2d5c69174e5e75e2a082b6e", "d99a08e47ccc61a0c7fd186f5fc43b369986715a5578f834b4324705f5921425", "a46acac66a508ef2522eec77771fd8fb697d79a9808a3de5d6f112c0a7effd2f", "3e5b09443f5683f50160de9572067deec4da5801384ebfc628182f641f9b3f13", "7925f87b45bdbfb47264acb7b37d058292cd754c8d5dce5cc0b2a05935751649", "d7e89a389ad79bcce2ee3f2cb85d0b7e9f2c70623f1b3ae4e18603352cea085b"),
        ("0102016c9e45bf9fcd7bc5036e3c2e972bed6264cf29988e59785274c6502d2b", "57ac9570ee671978bc641eb94c0e31eb21eb4ef5d7853da56a0ecc50676b1848", "8e44c9a0f91ed0c828668a6f8d194b03b139b2ec78d0f05f51a01eb838e03b3c", "58ae96dc8cadd8178ae0e3bcba4a5f824dd8b159a7afd533c4861ec52dbc4573", "97556bfbafdda5271117a74a212efdab0902146ff7a35ae9ee6986235fe51463", "ba1373dc2e542d9b00a90b09726a4581d0fdc7e4d3a384676e74bc8e68127d51"),
        ("52d68e7732bc13156cefd33dc459bff2be5653a3566c3d4fa23ab942f6766043", "78408cf78b253434bee6f24cf56c3e9a471ec54a6fc4e51e90817f9660fc714a", "6b69dca15f65419b93a64a700e0df743755f48447cd7d88b690ec1c179b6300f", "dd161b6fbee147492ad6c68ab9c6fd8c067518eec530236e32bc38d95673d20d", "c7950280a696dfe0ad08e1f0ceec805877388e58e7a7573012b939ac957aee78", "0acff17d76dddd014c08a7c0a26b51bcb21da07a3b5837a646a31cb206aa8b00"),
        ("c6f5ebb9d94d0d82716ebba90b240ee61f26ec6bc234178918d842d051ee8a41", "724465604de8b434765c05e53ba85134cd5093f295427106a576e65e1a99c443", "1272cc144eab2a7b4cf9877da962313ecb093fc4491d63e53ea865c4dab16602", "4b3a511a2736c2b6e7cac08e47cc5f1aed767f5e5877888fbd4e292f6c874f05", "41b186598c65584dfb11b6c4cf7bbcb152d558792cf2a58273615c713755c67d", "3336690583128d78716d7f25d904f07ffc816754023a10a5fb079579cd5c8a52"),
        ("dd93539a31e9c2b5dd66a5bd642f743cd11c6f64d4411757d1a41f0aed60594c", "1132ea3f86b7928a72d12242c66b7e4e484cfea1205d1445613c96bd5a0bf65a", "c3bf9c84243f95502f6582eccc49b842b2b024a6876f3bec4674810e9920247a", "01c63ddab7a055405038c8ff2a9bf28a19696d06f59e2b9c32e1b5c7476c4f27", "b961695aab31302b6b95827b9ec3f5ed88d070c2b3e402127068894c92556371", "822ad8391496830867c2c57b517851c8599ac22de87041a5cf6d10b2db68b036"),
        ("0e170b151670e2c3d932c254c8643c1e041421c003bb7a0bbffe3eb32c0c3169", "4b77fe0050ade3f673512d0695ee17f8fd13d8972f0392c0b80a3e509a19033d", "9d1e97efa6b53e27ec75d209f5de82aaaea61ab47046572e1fc06c9cb32aff0b", "6c8e0916661dc6ba4d84ef5a5d5354160228f95733be0ccc77097d03c7253426", "c39f0c14c6c2fecc65e1944e3376242606004928d4b7e84a06f4006392f22d2c", "106e3f9abc546ecdf5a16fffa96315d4d9ae0c3615e27aec03cae59a94609a43"),
        ("13b5e7857d0a0c37b8407af248c56e0c1fe9f4bdc1163d4b27a961356e651735", "1ab405cc295e1e9e307c739d83664b2259de939351012a121212c10a27052805", "1be805f5a35ba109d33ebf1de6ec2a27eb4a1946ebfe942fd4519dbc47fdc52c", "2d69ed51a7682ad5e8bced8fcc2bba2e78c788511318675d39bb2240956a3f3a", "f900e2b953aced9887c40655c55e23eac50a612a701513391597a02a4760ef2f", "b53c80f664e87dd10dd0bbd6363e37135cd8b901f889d9acaa14919f86d4fa6e"),
        ("f417eccb0e89c5cf84761a5978a1f11fcdccd4d174e6c726ce04f0e27033940b", "7937dfa763bc8d0209100df52b40a1bfcea20c6b8300a2fb21cbe78b70a3c943", "49251a4a6493de863e96069a4abec11085480dfefa9c9c566968970050ce4848", "6d4fcb73724553d28d86274ea4e192df9b6fe13cf8e66922f0cfd76ee1d65d4f", "68e00c24abcc37cd7b660d644c615060fe29c866f1e5252bac3908570090ca47", "f8edde28b217eab83dda64bb4797a8a273ba6f69afee0ef4daa8ee8994b77e4c"),
        ("9cbd64027f45101008a382429db76492fdf8bc4758c2da3d907fc5b8e9eb2553", "20917875652ee1ac97a229a1f7d2e8b7de7810be457f2f7ff1805355fdafdb1f", "a245fcdf61bed395f72d16ee33af582f3241b916d4d152410c579ce2853ada3d", "bc4edd77e473f1bc9f45ace3948a4d4adc71cd059e410abd8100190ee79b0173", "7c2cec8c19172f63700059a1a5e47bda1e80ac891243abbe9efe7163ec3b4a33", "d8cf460e12e0a7b1826a867ebc5476d8bf385b73a2e7e526e75708d231ee764c"),
        ("9a36bbfdf02738c80da9f28625665ad61734d49d078bfd88ac7eb7af51a5bc16", "429d15f65699054e24859f4b68a31326dade29d9495205ce125f2896e55fe148", "88e7db24f9f64501b55299cddc11bcb7054fae89e965f89839a66aa17058b153", "dcd3d0f347c13d16322e92d28d096efcf112fe7651dd0257bfdddf4537059e5f", "4599a5079a8e327ae923533bbdc246b03d55aac4bd38f8ba991f8f196c45db4d", "d26b227872364938bf8e1a162d0f41d194e6b810166302bc33d45e14fc962454"),
        ("1f6a710ee2343d3d8ed954fb9a62e67b4e88aebc303a2b2e762c7feb2ae69268", "8d1613ce3c32923fc658eac66a8040cf5efb61aee99951d591629abb215d7802", "b679c2147b350788c28ed867db9d2796cbc7f81f06553528cd097018c83c4d2e", "ac8084dc1e67cf7c54323fc205e3264bad83106b1ad47c03088f19a74c430b6b", "92535e40a502abfdc7806a3430e2a5acef8c4c0e47a0d958e4c9e42f09891a66", "1d641575d959dd5b2d22426ef6c6c9f6294ae837ceb446c069fecf9a8b3a8d1a"),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "0500000000000000000000000000000000000000000000000000000000000000", "e8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "4401000000000000000000000000000000000000000000000000000000000000", "2400000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "89e3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e23"),
        ("0000000000000000000000000000000000000000000000000000000000000000", "3930000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "3930000000000000000000000000000000000000000000000000000000000000", "b4cfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000"),
    ];

    #[test]
    fn operations_agree_with_python_integers() {
        for (a, b, mul, add, sub, inv) in TABLE {
            let (a, b) = (fe(a), fe(b));
            assert_eq!(hex(&a.mul(b).to_bytes()), *mul);
            assert_eq!(hex(&b.mul(a).to_bytes()), *mul);
            assert_eq!(hex(&a.add(b).to_bytes()), *add);
            assert_eq!(hex(&a.sub(b).to_bytes()), *sub);
            assert_eq!(hex(&a.invert().to_bytes()), *inv);
        }
    }

    #[test]
    fn the_encoding_is_canonical() {
        // p, p + 1 and 2^255 - 1 are all accepted and reduced
        let p = fe("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(p.equals(Fe::ZERO));
        assert_eq!(hex(&fe("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").to_bytes()), format!("01{}", "00".repeat(31)));
        assert_eq!(hex(&fe("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").to_bytes()), format!("12{}", "00".repeat(31)));
        // the top bit is dropped
        assert_eq!(fe("0100000000000000000000000000000000000000000000000000000000000080").to_bytes()[0], 1);
        // p - 1 is the largest value that stays as it is
        assert_eq!(hex(&fe("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").to_bytes()), "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    }

    #[test]
    fn negation_and_sign() {
        let one = Fe::ONE;
        assert!(one.is_negative());
        assert!(!one.neg().is_negative()); // p - 1 is even
        assert!(one.add(one.neg()).equals(Fe::ZERO));
        assert!(Fe::ZERO.neg().equals(Fe::ZERO));
        assert!(!Fe::ZERO.is_negative());
        assert_eq!(hex(&one.neg().to_bytes()), "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    }

    #[test]
    fn constants_match_their_definitions() {
        // d = -121665 / 121666
        let num = small(121665).neg();
        let den = small(121666);
        assert!(Fe::D.equals(num.mul(den.invert())));
        assert!(Fe::D2.equals(Fe::D.add(Fe::D)));
        assert!(Fe::SQRT_M1.square().equals(Fe::ONE.neg()));
        // the base point is on the curve: -x^2 + y^2 = 1 + d x^2 y^2, and y = 4/5
        let (x, y) = (Fe::BASE_X, Fe::BASE_Y);
        let lhs = y.square().sub(x.square());
        let rhs = Fe::ONE.add(Fe::D.mul(x.square()).mul(y.square()));
        assert!(lhs.equals(rhs));
        assert!(y.mul(small(5)).equals(small(4)));
        assert!(!x.is_negative());
        // and the limbs are what the encodings decode to
        assert_eq!(hex(&Fe::D.to_bytes()), "a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352");
        assert_eq!(hex(&Fe::D2.to_bytes()), "59f1b226949bd6eb56b183829a14e00030d1f3eef2808e19e7fcdf56dcd90624");
        assert_eq!(hex(&Fe::SQRT_M1.to_bytes()), "b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b");
        assert_eq!(hex(&Fe::BASE_X.to_bytes()), "1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921");
        assert_eq!(hex(&Fe::BASE_Y.to_bytes()), "5866666666666666666666666666666666666666666666666666666666666666");
    }

    #[test]
    fn pow22523_is_the_square_root_exponent() {
        // x^((p-5)/8) squared three times is x^(p-5), and x^(p-1) = 1 for x != 0, so
        // x^(8 * ((p-5)/8)) * x^4 = 1
        for (a, _, _, _, _, _) in TABLE {
            let a = fe(a);
            if a.equals(Fe::ZERO) {
                continue;
            }
            let r = a.pow22523();
            let r8 = r.square().square().square();
            assert!(r8.mul(a.square().square()).equals(Fe::ONE));
        }
        assert!(Fe::ZERO.pow22523().equals(Fe::ZERO));
    }

    /// The squaring, the addition chains and the multiplication without its second carry pass, against the
    /// definitions they replaced (B-103): a square is a product with itself, the inverse is x^(p-2) by plain
    /// square-and-multiply, and limbs stay below 2^51 plus a few bits after every operation, so chains of them
    /// cannot overflow. Random inputs, including limbs at the top of the slack that `add` leaves.
    #[test]
    fn the_fast_paths_agree_with_the_plain_definitions() {
        fn by_bits(x: Fe, bits: impl Iterator<Item = bool>) -> Fe {
            let mut r = Fe::ONE;
            for b in bits {
                r = r.mul(r);
                if b {
                    r = r.mul(x);
                }
            }
            r
        }
        // p - 2: bits 254..5 set, then 01011; (p - 5) / 8: bits 251..2 set, bit 1 clear, bit 0 set
        let inv_bits = || (0..=254u32).rev().map(|i| i >= 5 || matches!(i, 3 | 1 | 0));
        let sqrt_bits = || (0..=251u32).rev().map(|i| i >= 2 || i == 0);
        let mut rng = crate::fuzz::Rng::new(0x25519);
        let limit = (1u64 << 52) - 1;
        for i in 0..400 {
            let x = if i % 4 == 0 {
                // unreduced, as `add` leaves them: each limb below 2^52
                Fe(std::array::from_fn(|_| rng.next_u64() & limit))
            } else {
                Fe::from_bytes(&rng.bytes(32).try_into().unwrap())
            };
            let sq = x.square();
            assert!(sq.equals(x.mul(x)), "square");
            assert!(sq.0.iter().all(|&l| l < (1u64 << 51) + (1 << 12)), "square leaves the slack");
            assert!(x.mul(x).0.iter().all(|&l| l < (1u64 << 51) + (1 << 12)), "mul leaves the slack");
            if i % 20 == 0 {
                assert!(x.invert().equals(by_bits(x, inv_bits())), "invert");
                assert!(x.pow22523().equals(by_bits(x, sqrt_bits())), "pow22523");
            }
        }
    }

    #[test]
    fn ring_laws_hold_on_unreduced_limbs() {
        // chains of operations without reducing in between, checked against the distributive law
        let vals: Vec<Fe> = TABLE.iter().map(|r| fe(r.0)).collect();
        for w in vals.windows(3) {
            let (a, b, c) = (w[0], w[1], w[2]);
            assert!(a.add(b).mul(c).equals(a.mul(c).add(b.mul(c))));
            assert!(a.sub(b).mul(c).equals(a.mul(c).sub(b.mul(c))));
            assert!(a.mul(b).mul(c).equals(a.mul(b.mul(c))));
            assert!(a.square().equals(a.mul(a)));
        }
    }
}
