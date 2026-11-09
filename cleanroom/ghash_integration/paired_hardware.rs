extern crate pratique_base;
extern crate pratique_new;
use std::hint::black_box;
use std::time::Instant;
fn measure(size: usize, calls: usize, mut before: impl FnMut(), mut after: impl FnMut(), name: &str) {
    for _ in 0..32 { before(); after(); }
    let mut results = Vec::new();
    for run in 0..17 {
        let time = |op: &mut dyn FnMut()| {
            let start = Instant::now();
            for _ in 0..calls { op(); }
            start.elapsed().as_secs_f64()
        };
        let (a,b) = if run & 1 == 0 { (time(&mut before), time(&mut after)) } else { let b=time(&mut after); (time(&mut before),b) };
        results.push((size as f64 * calls as f64 / a / 1e6, size as f64 * calls as f64 / b / 1e6));
    }
    let mut before: Vec<_> = results.iter().map(|v|v.0).collect();
    let mut after: Vec<_> = results.iter().map(|v|v.1).collect();
    let mut change: Vec<_> = results.iter().map(|v|(v.1 / v.0 - 1.0)*100.0).collect();
    before.sort_by(f64::total_cmp); after.sort_by(f64::total_cmp); change.sort_by(f64::total_cmp);
    println!("{name},{size},{:.3},{:.3},{:.3}", before[8],after[8],change[8]);
    for (i,(before,after)) in results.iter().enumerate() { println!("sample,{name},{size},{i},{before:.3},{after:.3}"); }
}
fn main() {
    assert!(pratique_base::crypto::aes::hardware_accelerated());
    assert!(pratique_new::crypto::aes::hardware_accelerated());
    println!("cipher,bytes,baseline_MBps,integrated_MBps,median_paired_change_percent");
    let nonce=[3u8;12];
    for keylen in [16,32] {
        let before=pratique_base::crypto::gcm::AesGcm::new(&vec![1u8;keylen]);
        let after=pratique_new::crypto::gcm::AesGcm::new(&vec![1u8;keylen]);
        for (size,calls) in [(1<<20,128),(16384,8192)] {
            let mut b=vec![0xa5u8;size+16]; let mut a=b.clone();
            measure(size,calls,
                || { before.seal_in_place(black_box(&nonce),black_box(b""),black_box(&mut b)); black_box(&b); },
                || { after.seal_in_place(black_box(&nonce),black_box(b""),black_box(&mut a)); black_box(&a); },
                &format!("AES{}-GCM",keylen*8));
        }
    }
}
