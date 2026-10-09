//! Overwriting secrets with zeros when they are dropped. Behind the `net` feature: the volatile
//! writes need `unsafe`, and the pure verification part of the crate handles only public data.

/// Types whose contents can be overwritten with zeros in a way the compiler may not optimise away.
///
/// This is best effort: it clears the value where it lives, but it cannot reach copies the
/// compiler made when moving it, CPU registers, or pages the operating system swapped out.
pub trait Zeroize {
    fn zeroize(&mut self);

    /// Zeroizes every element of a slice of this type: one by one, unless the type has a quicker way (bytes do: eight at a
    /// time).
    #[doc(hidden)]
    fn zeroize_all(all: &mut [Self])
    where
        Self: Sized,
    {
        for x in all.iter_mut() {
            x.zeroize();
        }
    }
}

macro_rules! zeroize_primitive {
    ($($t:ty),*) => {$(
        impl Zeroize for $t {
            #[inline]
            fn zeroize(&mut self) {
                // SAFETY: `self` is a valid, aligned, exclusive reference to a plain integer.
                // A volatile write is not removed even when the value is never read again.
                unsafe { core::ptr::write_volatile(self, 0) }
            }
        }
    )*};
}
zeroize_primitive!(u16, u32, u64, u128, usize, i8);

impl Zeroize for u8 {
    #[inline]
    fn zeroize(&mut self) {
        // SAFETY: as for the other integers above.
        unsafe { core::ptr::write_volatile(self, 0) }
    }

    /// Bytes eight at a time where they are aligned for it: a volatile write cannot be merged with its neighbours, so a
    /// byte at a time is a store per byte (wiping 256 bytes that way was a third of a 100-byte ChaCha20-Poly1305 seal, B-103).
    fn zeroize_all(all: &mut [u8]) {
        // SAFETY: every bit pattern is a valid u64 and a valid u8, so viewing the aligned middle of a byte slice as u64s is
        // sound; `align_to_mut` gives only whole, aligned u64s in the middle and the rest as bytes.
        let (head, middle, tail) = unsafe { all.align_to_mut::<u64>() };
        for b in head.iter_mut().chain(tail.iter_mut()) {
            b.zeroize();
        }
        for w in middle.iter_mut() {
            w.zeroize();
        }
    }
}

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        T::zeroize_all(self);
        // Keep the compiler from moving later reads or frees of this memory before the wipe.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<T: Zeroize> Zeroize for Vec<T> {
    /// Overwrites every element, then empties the vector (the allocation is kept).
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        self.clear();
    }
}

/// Owns a secret and zeroizes it when dropped.
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }
}

impl<T: Zeroize> std::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> std::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Zeroizing(self.0.clone())
    }
}

impl<T: Zeroize> std::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Zeroizing(..)")
    }
}

#[cfg(test)]
mod zeroize_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn wipes_arrays_slices_and_vectors() {
        let mut a = [0xffu8; 32];
        a.zeroize();
        assert_eq!(a, [0u8; 32]);
        let mut w = [u32::MAX; 8];
        w.zeroize();
        assert_eq!(w, [0u32; 8]);
        let mut nested = vec![[7u8; 16]; 5];
        nested.zeroize();
        assert!(nested.is_empty());
        let mut v = vec![9u8; 100];
        let ptr = v.as_ptr();
        v.zeroize();
        assert!(v.is_empty());
        // The allocation is still ours (clear() keeps it): check the bytes really are zero.
        assert_eq!(v.capacity(), 100);
        // SAFETY: capacity 100, pointer unchanged, we only read bytes that were initialised to 9
        // and then overwritten with 0 by `zeroize`.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, 100) };
        assert!(bytes.iter().all(|&b| b == 0));
        let mut big = 0xdead_beef_u128 << 64;
        big.zeroize();
        assert_eq!(big, 0);
    }

    /// Bytes are wiped eight at a time in the aligned middle and one at a time around it: every length from 0 to 80 at
    /// every offset from an aligned start, and nothing outside the slice is touched.
    #[test]
    fn byte_slices_are_wiped_whatever_their_alignment() {
        for start in 0..9usize {
            for len in 0..=80usize {
                let mut buf = [0xa5a5_a5a5_a5a5_a5a5u64; 16]; // 128 bytes, aligned for u64
                // SAFETY: the u64 array is 128 initialised bytes, viewed as bytes for the test
                let bytes = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 128) };
                bytes[start..start + len].zeroize();
                for (i, &b) in bytes.iter().enumerate() {
                    let inside = (start..start + len).contains(&i);
                    assert_eq!(b, if inside { 0 } else { 0xa5 }, "start {start}, length {len}, byte {i}");
                }
            }
        }
    }

    struct Probe(Rc<Cell<u32>>);

    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn zeroizing_wipes_exactly_once_on_drop_and_hides_contents() {
        let count = Rc::new(Cell::new(0));
        {
            let z = Zeroizing::new(Probe(count.clone()));
            assert_eq!(format!("{:?}", z), "Zeroizing(..)");
            assert_eq!(count.get(), 0);
        }
        assert_eq!(count.get(), 1);
        let kept = Zeroizing::new(vec![1u8, 2, 3]);
        assert_eq!(&kept[..], &[1, 2, 3]); // Deref
        let copy = kept.clone();
        drop(kept);
        assert_eq!(&copy[..], &[1, 2, 3]);
    }
}
