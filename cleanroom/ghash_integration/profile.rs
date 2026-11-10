//! Integration measurements. No primitive expressions are defined here.
use super::aes::{self, Aes, Backend};
use super::gcm::AesGcm;
use super::ghash::GhashKey;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn measure(name: &str, size: usize, mut op: impl FnMut()) {
    for _ in 0..3 {
        op();
    }
    let start = Instant::now();
    let mut calls = 0;
    while start.elapsed() < Duration::from_millis(40) {
        op();
        calls += 1;
    }
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..calls {
            op();
        }
        samples.push(start.elapsed().as_secs_f64() / calls as f64);
    }
    samples.sort_by(f64::total_cmp);
    let secs = samples[3];
    println!(
        "{name},{size},{:.3},{:.3}",
        secs * 1e9,
        size as f64 / secs / 1e6
    );
}

#[test]
#[ignore = "sequential release throughput and component profile"]
fn release_profile() {
    println!("hardware_available={}", aes::hardware_accelerated());
    println!(
        "data_independent_timing_available={}",
        super::dit::Dit::available()
    );
    println!("operation,bytes,ns_per_call,decimal_MB_per_second");
    let nonce = [3u8; 12];
    let mut backends = vec![Backend::Portable];
    if aes::hardware_accelerated() {
        backends.push(Backend::Hardware);
    }
    for backend in backends {
        for keylen in [16, 32] {
            let key = vec![1u8; keylen];
            let aes = Aes::with_backend(&key, backend);
            let gcm = AesGcm::with_backend(&key, backend);
            let h = aes.encrypt_block(&[0u8; 16]);
            let hash = GhashKey::new(&h, backend);
            for size in [1 << 20, 16384] {
                let mut data = vec![0xa5u8; size];
                let mut buf = vec![0xa5u8; size + 16];
                measure(&format!("AES{}-CTR-{backend:?}", keylen * 8), size, || {
                    aes.ctr_xor(black_box(&nonce), 2, black_box(&mut data));
                    black_box(&data);
                });
                if keylen == 16 {
                    measure(&format!("GHASH-{backend:?}"), size, || {
                        black_box(hash.hash(black_box(b""), black_box(&data)));
                    });
                }
                measure(
                    &format!("AES{}-GCM-seal-{backend:?}", keylen * 8),
                    size,
                    || {
                        gcm.seal_in_place(black_box(&nonce), black_box(b""), black_box(&mut buf));
                        black_box(&buf);
                    },
                );
                // Reset between successful opens to retain valid ciphertext and tag.
                let sealed = gcm.seal(&nonce, b"", &data);
                measure(
                    &format!("AES{}-GCM-open-copy-{backend:?}", keylen * 8),
                    size,
                    || {
                        buf.copy_from_slice(&sealed);
                        assert_eq!(
                            gcm.open_in_place(
                                black_box(&nonce),
                                black_box(b""),
                                black_box(&mut buf)
                            ),
                            Some(size)
                        );
                        black_box(&buf);
                    },
                );
            }
            measure(&format!("AES{}-GCM-key-{backend:?}", keylen * 8), 0, || {
                black_box(AesGcm::with_backend(black_box(&key), backend));
            });
        }
    }
}
