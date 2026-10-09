//! ECDSA P-256 verification with its point operations compiled for x86-64 CPUs with BMI2 (B-104): the code of `ecdsa`
//! (`Group::double_inline` and the two additions, `#[inline(always)]` down to the field arithmetic) compiled once more
//! with the feature, so that its products use `mulx`, which leaves the flags alone and frees the compiler's scheduling
//! of the carries: about an eighth quicker on the x86-64 VM of BENCHMARKS.md. (ADX's two carry chains would be the next
//! step, but the compiler does not use them.)
//!
//! Found at run time, like the AES and SHA instructions (`aes_hw`, `sha2_hw`); with `--cfg pratique_portable`, or on
//! another CPU, `detect` offers nothing and `ecdsa` uses its own copy. Verification handles only public data, so there is
//! no timing property to keep.

use super::ecdsa::Verify;

/// The P-256 verification for this CPU, if it has the feature.
pub(super) fn detect() -> Option<Verify> {
    #[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
    {
        x86::detect()
    }
    #[cfg(not(all(target_arch = "x86_64", not(pratique_portable))))]
    {
        None
    }
}

#[cfg(all(target_arch = "x86_64", not(pratique_portable)))]
mod x86 {
    use super::super::ecdsa::{self, Aff, Group, Jac, Points};
    use super::Verify;

    pub(super) fn detect() -> Option<Verify> {
        std::is_x86_feature_detected!("bmi2").then_some(ecdsa::p256_verify_with::<Bmi2> as Verify)
    }

    /// The point operations compiled with BMI2. Only `detect` hands out a verification that uses them, and only on a
    /// CPU with BMI2 (and the tests check for it first).
    pub(super) struct Bmi2;

    impl Points<4> for Bmi2 {
        fn double(g: &Group<4>, p: &Jac<4>) -> Jac<4> {
            // SAFETY: as the type says: used only where the CPU has BMI2.
            unsafe { double(g, p) }
        }
        fn add(g: &Group<4>, p: &Jac<4>, q: &Jac<4>) -> Jac<4> {
            // SAFETY: as above.
            unsafe { add(g, p, q) }
        }
        fn add_affine(g: &Group<4>, p: &Jac<4>, q: &Aff<4>) -> Jac<4> {
            // SAFETY: as above.
            unsafe { add_affine(g, p, q) }
        }
    }

    /// # Safety
    /// Only on a CPU with BMI2; the same for the two below.
    #[target_feature(enable = "bmi2")]
    unsafe fn double(g: &Group<4>, p: &Jac<4>) -> Jac<4> {
        g.double_inline(p)
    }

    #[target_feature(enable = "bmi2")]
    unsafe fn add(g: &Group<4>, p: &Jac<4>, q: &Jac<4>) -> Jac<4> {
        g.add_inline(p, q)
    }

    #[target_feature(enable = "bmi2")]
    unsafe fn add_affine(g: &Group<4>, p: &Jac<4>, q: &Aff<4>) -> Jac<4> {
        g.add_affine_inline(p, q)
    }

    #[cfg(test)]
    mod tests {
        use super::super::super::ecdsa;
        use super::Bmi2;

        /// The point operations with BMI2 give what the plain ones give, on random scalars and the special cases of the
        /// group law; and a verification with them agrees with the plain one on valid and altered signatures.
        #[test]
        fn the_bmi2_point_operations_agree_with_the_plain_ones() {
            if !std::is_x86_feature_detected!("bmi2") {
                eprintln!("no BMI2 on this CPU: nothing to check");
                return;
            }
            ecdsa::tests::check_p256_points::<Bmi2>();
            // RFC 6979 A.2.5, message "sample", SHA-256
            let public = crate::util::unhex("0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
            let sig = crate::util::unhex("3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
            let digest = crate::crypto::sha2::HashAlg::Sha256.digest(b"sample");
            assert!(ecdsa::p256_verify_with::<Bmi2>(&public, &digest, &sig));
            for i in 0..sig.len() {
                let mut bad = sig.clone();
                bad[i] ^= 1 << (i % 8);
                assert_eq!(ecdsa::p256_verify_with::<Bmi2>(&public, &digest, &bad), ecdsa::p256_verify(&public, &digest, &bad), "byte {i}");
            }
        }
    }
}
