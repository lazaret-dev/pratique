//! Clean-room, bitsliced AES forward S-box.
//!
//! This module implements the construction in NIST FIPS 197: multiplicative
//! inversion in GF(2^8), followed by the affine transformation from Sec. 5.1.1.
//! The field modulus is x^8 + x^4 + x^3 + x + 1.  Every operation applies to
//! 64 independent lanes at once, with the least-significant bit in plane zero.

pub(crate) type Planes = [u64; 8];

/// Multiply every lane in `a` by every corresponding lane in `b` in the AES
/// field.  Both loop bounds and all memory addresses are independent of data.
#[inline(always)]
fn gf_mul(mut a: Planes, b: Planes) -> Planes {
    let mut product = [0u64; 8];

    for bit in 0..8 {
        let selected_lanes = b[bit];
        for plane in 0..8 {
            product[plane] ^= a[plane] & selected_lanes;
        }

        // Multiply by x and reduce x^8 with
        // x^8 = x^4 + x^3 + x + 1 in characteristic two.
        let high = a[7];
        a = [
            high,
            a[0] ^ high,
            a[1],
            a[2] ^ high,
            a[3] ^ high,
            a[4],
            a[5],
            a[6],
        ];
    }

    product
}

/// Square every lane in the AES field.  This is the linear map obtained by
/// squaring the polynomial basis elements and reducing by the AES modulus.
#[inline(always)]
fn gf_square(a: Planes) -> Planes {
    [
        a[0] ^ a[4] ^ a[6],
        a[4] ^ a[6] ^ a[7],
        a[1] ^ a[5],
        a[4] ^ a[5] ^ a[6] ^ a[7],
        a[2] ^ a[4] ^ a[7],
        a[5] ^ a[6],
        a[3] ^ a[5],
        a[6] ^ a[7],
    ]
}

/// Return the FIPS 197 forward AES S-box for 64 bitsliced bytes.
///
/// The fixed addition chain computes `a^254`, which is the multiplicative
/// inverse for nonzero field elements.  It maps zero to zero without a special
/// case.  There are no tables, secret-dependent branches, or unsafe operations.
#[inline(always)]
pub(crate) fn sbox(q: &Planes) -> Planes {
    // 2, 3, 6, 12, 15, 30, 60, 120, 240, 252, 254.
    let x2 = gf_square(*q);
    let x3 = gf_mul(x2, *q);
    let x6 = gf_square(x3);
    let x12 = gf_square(x6);
    let x15 = gf_mul(x12, x3);
    let x30 = gf_square(x15);
    let x60 = gf_square(x30);
    let x120 = gf_square(x60);
    let x240 = gf_square(x120);
    let x252 = gf_mul(x240, x12);
    let inverse = gf_mul(x252, x2);

    // FIPS 197, Eq. 5.1.  A set bit in 0x63 is represented by all lanes set.
    let one = !0u64;
    [
        inverse[0] ^ inverse[4] ^ inverse[5] ^ inverse[6] ^ inverse[7] ^ one,
        inverse[1] ^ inverse[5] ^ inverse[6] ^ inverse[7] ^ inverse[0] ^ one,
        inverse[2] ^ inverse[6] ^ inverse[7] ^ inverse[0] ^ inverse[1],
        inverse[3] ^ inverse[7] ^ inverse[0] ^ inverse[1] ^ inverse[2],
        inverse[4] ^ inverse[0] ^ inverse[1] ^ inverse[2] ^ inverse[3],
        inverse[5] ^ inverse[1] ^ inverse[2] ^ inverse[3] ^ inverse[4] ^ one,
        inverse[6] ^ inverse[2] ^ inverse[3] ^ inverse[4] ^ inverse[5] ^ one,
        inverse[7] ^ inverse[3] ^ inverse[4] ^ inverse[5] ^ inverse[6],
    ]
}

#[cfg(test)]
mod tests {
    use super::{gf_mul, sbox, Planes};

    // NIST FIPS 197, Table 4.
    const FIPS_SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    fn pack(bytes: &[u8; 64]) -> Planes {
        let mut planes = [0u64; 8];
        for (lane, byte) in bytes.iter().copied().enumerate() {
            for (plane, bits) in planes.iter_mut().enumerate() {
                *bits |= u64::from((byte >> plane) & 1) << lane;
            }
        }
        planes
    }

    fn unpack(planes: &Planes) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for (lane, byte) in bytes.iter_mut().enumerate() {
            for (plane, bits) in planes.iter().copied().enumerate() {
                *byte |= (((bits >> lane) & 1) as u8) << plane;
            }
        }
        bytes
    }

    fn scalar_field_mul(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                product ^= a;
            }
            let high = a >> 7;
            a <<= 1;
            if high != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        product
    }

    #[test]
    fn field_multiplication_matches_polynomial_oracle() {
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let mut a_lanes = [0u8; 64];
                let mut b_lanes = [0u8; 64];
                a_lanes.fill(a as u8);
                b_lanes.fill(b as u8);
                let got = unpack(&gf_mul(pack(&a_lanes), pack(&b_lanes)));
                assert_eq!(got[0], scalar_field_mul(a as u8, b as u8));
            }
        }
    }

    #[test]
    fn all_fips_sbox_values() {
        for chunk in 0..4 {
            let mut input = [0u8; 64];
            for (lane, byte) in input.iter_mut().enumerate() {
                *byte = (chunk * 64 + lane) as u8;
            }
            let got = unpack(&sbox(&pack(&input)));
            for (lane, byte) in got.iter().copied().enumerate() {
                assert_eq!(byte, FIPS_SBOX[chunk * 64 + lane]);
            }
        }
    }

    #[test]
    fn every_input_plane_and_lane_position() {
        for plane in 0..8 {
            for lane in 0..64 {
                let mut input = [0u8; 64];
                input[lane] = 1 << plane;
                let got = unpack(&sbox(&pack(&input)));
                for (got_lane, byte) in got.iter().copied().enumerate() {
                    let expected = if got_lane == lane {
                        FIPS_SBOX[1 << plane]
                    } else {
                        FIPS_SBOX[0]
                    };
                    assert_eq!(byte, expected, "input plane {plane}, lane {lane}");
                }
            }
        }
    }

    #[test]
    fn mixed_simultaneous_bytes() {
        let mut input = [0u8; 64];
        for (lane, byte) in input.iter_mut().enumerate() {
            *byte = (lane as u8).wrapping_mul(197).wrapping_add(113);
        }
        let got = unpack(&sbox(&pack(&input)));
        for lane in 0..64 {
            assert_eq!(got[lane], FIPS_SBOX[input[lane] as usize]);
        }
    }
}
