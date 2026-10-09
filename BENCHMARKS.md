# Benchmarks

How fast the crate is, how to measure it, and how to build an application for speed (BACKLOG B-54 and B-55).

## Running them

```sh
sh tools/bench.sh            # both benchmarks, compared with this machine's last run, then recorded
sh tools/bench.sh --quick    # a tenth of the network samples
sh tools/bench.sh --no-record --tsv run.tsv   # compare only, and keep this run's figures in run.tsv
```

`tools/bench.sh` builds and runs two examples, prints every figure, compares each with the last one recorded for this
machine in `bench/results.tsv`, marks those more than 15 percent worse as `SLOWER`, and appends the run to the file. The
machine's label is the system, the architecture and the CPU's model (never the host name), or `--label NAME`.
`tools/native_check.sh` runs it with `--no-record` and keeps the figures in `native_check_logs/bench.tsv`, to be added to
`bench/results.tsv` by hand.

* `examples/bench.rs`, the primitives, one thread: each AEAD sealing messages of 1 MiB, 16 KiB (a TLS record), 1 KB and
  100 B; AES-128-CTR and SHA-256; X25519; ECDSA P-256 and P-384, Ed25519 and RSA-2048 and RSA-4096 verification (and the
  RSA key's set-up, which is paid once per certificate); a certificate chain check; parsing a certificate and loading the
  system's CA bundle.
* `examples/bench_net.rs` (needs `--features server`), on loopback against the crate's own TLS 1.3 server in the same
  process: the latency of a full TLS 1.3 handshake with X25519, and with P-256 and P-384 (which this client reaches by a
  HelloRetryRequest, as it offers an X25519 key share first), and of a resumed one; HTTP/1.1 requests per second with
  keep-alive, with a connection each (resumed, and with full handshakes), HTTP/2 requests on one connection from one
  thread and from eight; small messages of 100 B and 1000 B, a record each; and a 256 MiB download for each cipher suite.

### Reading the figures

* Each primitive's figure is the best of five batches of about 50 ms after one that warms up; rates are the best of three
  runs; latencies are medians of 400 handshakes, with the 90th percentile printed beside them.
* On a shared or virtual machine two runs of the same build differ by 10 to 30 percent, more for the network figures,
  where the client and the server share the CPUs (on the 2-vCPU VM below, a single-threaded figure once came out 1.8 times
  slower on an unchanged build). A `SLOWER` mark is a reason to run again, alternating the old build and the new, before
  calling it a regression.
* The network figures are for comparing builds and machines. The server's certificate is Ed25519 (what the test server
  signs with), so a handshake here verifies one Ed25519 signature where a real one verifies two or three ECDSA or RSA
  signatures (`examples/bench.rs` has their costs), and there is no network in between.

## Recorded results

All of them are in `bench/results.tsv`, one line per figure and run. The first run, on 2026-10-08, on the VM these changes
were made on (a Cascade Lake Xeon at 2.8 GHz, 2 vCPUs, with AES-NI, AVX2 and AVX-512 but no SHA extensions), in brief:

| Figure | |
|---|---|
| AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305, 16 KiB records | 2.9 / 2.5 / 1.2 GB/s |
| the same, 100 B messages | 712 / 619 / 183 MB/s |
| SHA-256 | 194 MB/s |
| ECDSA P-256 / P-384, Ed25519 verification | 0.09 / 0.40 / 0.16 ms |
| RSA-2048 / RSA-4096 verification (and the key's set-up) | 0.036 / 0.14 ms (0.023 / 0.095 ms) |
| TLS 1.3 handshake on loopback: full X25519 / resumed | 1.8 / 1.1 ms (median) |
| HTTP/1.1 requests: keep-alive / a connection each, resumed / full | 12,100 / 800 / 420 per second |
| HTTP/2 requests on one connection: one thread / eight | 10,400 / 21,900 per second |
| download over TLS 1.3: AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 | 1.0 / 1.0 / 0.73 GB/s |

On the Apple M5 Max (aarch64 macOS, 18 cores; `tools/native_check.sh` on 2026-10-08, after B-85 gave AES-GCM a single pass
on ARM; the bitsliced AES does 0.24 / 0.20 GB/s there):

| Figure | |
|---|---|
| AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305, 16 KiB records | 12.7 / 10.1 / 1.3 GB/s |
| the same, 100 B messages | 1,275 / 1,176 / 316 MB/s |
| SHA-256 | 445 MB/s |
| ECDSA P-256 / P-384, Ed25519 verification | 0.035 / 0.13 / 0.053 ms |
| RSA-2048 / RSA-4096 verification (and the key's set-up) | 0.018 / 0.074 ms (0.012 / 0.053 ms) |
| TLS 1.3 handshake on loopback: full X25519 / resumed | 0.55 / 0.30 ms (median) |
| HTTP/1.1 requests: keep-alive / a connection each, resumed / full | 59,600 / 2,640 / 1,750 per second |
| HTTP/2 requests on one connection: one thread / eight | 50,400 / 97,900 per second |
| download over TLS 1.3: AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 | 4.1 / 3.8 / 1.0 GB/s |

As a check on the AES-GCM figures, in a Linux VM on the same Mac the benchmark gave 11.3 / 9.8 GB/s at 16 KiB where
OpenSSL 3.0.2's `openssl speed -evp` gave 9.1 / 8.9.

What B-57 and B-49 changed, measured on the same VM: ChaCha20-Poly1305 from 0.64 to 1.2 GB/s on 16 KiB records (an AVX2
keystream and Poly1305 in radix 2^64); P-256 verification from about 110 to 91 us (its prime's own reduction); RSA-2048
verification from 67 to 37 us and its key's set-up from 39 to 23 us, RSA-4096 from 247 to 137 and 166 to 95 us (fixed-size
arithmetic and a squaring); the chain check from 0.21 to 0.15 ms. The details are in BACKLOG.md.

What B-103 changed (`examples/bench.rs`, 2026-10-08), on the same VM and in the Linux VM on the M5 (the tables above are
from before it; `tools/bench.sh` records the next run):

| Figure | x86-64 VM: before, after | M5 VM, after |
|---|---|---|
| AES-128-GCM / AES-256-GCM, 16 KiB records | 2.9 / 2.5, 4.1 / 3.1 GB/s | 11.5 / 9.8 GB/s |
| AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305, 100 B messages | 712 / 619 / 183, 1,113 / 929 / 325 MB/s | 1,682 / 1,488 / 512 MB/s |
| ChaCha20-Poly1305, 16 KiB records | 1.2, 1.2 GB/s | 2.7 GB/s (1.3 before) |
| SHA-256 | 194, 200 MB/s (no SHA extensions here) | 3,487 MB/s (380 before) |
| X25519, one multiplication (key generation) | 0.022 ms | 0.0076 ms |
| Ed25519 verification | 0.16, 0.073 ms | 0.024 ms |
| RSA-2048 verification (and the key's set-up) | 0.036 (0.023), 0.035 (0.0033) ms | 0.012 (0.0016) ms |
| RSA-4096 verification (and the key's set-up) | 0.14 (0.095), 0.137 (0.0091) ms | 0.046 (0.0048) ms |

What B-104 changed (`examples/bench.rs`, 2026-10-08, two runs each; before is B-103's):

| Figure | x86-64 VM: before, after | M5 VM: before, after |
|---|---|---|
| ECDSA P-256 / P-384 verification | 0.085 / 0.40, 0.075 / 0.37 to 0.38 ms | 0.033 / 0.131, 0.031 / 0.122 ms |
| X25519, the ladder (a shared secret) | 0.064, 0.044 ms | about 0.019, 0.0176 ms |
| X25519, key generation | 0.022, 0.019 ms | 0.0076, 0.0068 ms |
| Ed25519 verification | 0.073, 0.061 to 0.062 ms | 0.024, 0.0225 ms |
| AES-128-GCM, 16 KiB / 1 KB / 100 B | 3.9 / 3.05 / 1.1, 4.3 to 4.5 / 3.3 / 1.15 GB/s | unchanged (11.6 / 7.8 / 1.69) |
| AES-256-GCM, 16 KiB | 3.0 to 3.1, 3.27 GB/s | unchanged (9.9) |
| ChaCha20-Poly1305, 16 KiB / 1 KB / 100 B | 1.22 / 0.83 / 0.32, 1.40 / 0.82 to 0.85 / 0.32 GB/s | unchanged (2.69 / 1.40 / 0.51) |

What B-109 added (`examples/bench.rs`, 2026-10-08, the x86-64 VM): the cost of signing, which a TLS server pays once per
full handshake, and of ECDH on the NIST curves, which a client pays after a HelloRetryRequest for one:

| Figure | x86-64 VM |
|---|---|
| ECDSA P-256 / P-384 signing (hedged RFC 6979 nonce) | 0.42 / 1.01 ms |
| Ed25519 signing | 0.021 ms |
| RSA-2048 / RSA-3072 / RSA-4096 signing (PSS, CRT, blinded, checked) | 1.26 / 4.96 / 12.0 ms |
| ECDH P-256 / P-384 (a shared secret) | 0.38 / 0.93 ms |

ECDSA signing is nearly all [k]G by `ecdh.rs`'s windows over a variable base; a fixed-base table, as X25519 key generation
has, would cut it about five times, and RSA signing takes about twice OpenSSL's time (both B-115 in BACKLOG.md).

The ladder has a row of its own since B-104 (`X25519 (shared secret, the ladder)`); the row before it is key generation,
which B-103 took off the ladder. On x86-64 the X25519 ladder and ECDSA P-256's point operations run from copies compiled for
BMI2 where the CPU has it, and Poly1305 takes four blocks at a time with AVX2 from 2 KiB (B-104 in BACKLOG.md).

## Against other Rust libraries

`bench/compare` (a crate of its own, like `fuzz/`, so the library keeps no dependencies) runs the same operations through
pratique, ring 0.17.14, aws-lc-rs 1.18.1 and RustCrypto (aes-gcm 0.11.1, chacha20poly1305 0.11.0, sha2 0.11.0, p256 0.14.0,
ed25519-dalek 3.0.0, rsa 0.9.10, x25519-dalek 3.0.0), each through its own API and timed by one loop (the best of five batches
of 50 ms after a warm-up). For TLS, every client (pratique, and rustls 0.23.45 with ring and with aws-lc-rs) connects to the
same rustls + aws-lc-rs server on loopback with a chain of two ECDSA P-256 certificates, X25519 only, TLS 1.3, no resumption;
"client CPU" is the client thread's own CPU time. The signature rows parse the public key too, as a TLS client does for each
certificate; ring and aws-lc-rs draw a random X25519 key where the others are given one.

```sh
cd bench/compare && sh make_certs.sh && cargo run --release      # prims, then tls; or `-- prims`, `-- tls`, `-- hs` (the
                                                                 # handshakes alone), `-- prof 40` (40 of ours alone, for a profiler)
```

First run, 2026-10-08, before B-103, on an Apple M5 Max (in the Linux VM of the Cowork sandbox, 4 vCPUs; the AES-GCM figures
there were within about 10 percent of macOS's own) and on the 2-vCPU x86-64 VM of the rest of this file (two runs each):

| | M5: pratique | ring | aws-lc-rs | RustCrypto | x86-64: pratique | ring | aws-lc-rs | RustCrypto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AES-128-GCM seal, 16 KiB (GB/s) | **11.3** | 9.6 | 9.5 | 3.2 | 2.8 | 4.5 | 4.8 | 1.4 |
| AES-128-GCM seal, 1 KiB (GB/s) | 7.6 | 7.9 | 6.9 | 3.0 | 2.6 | 3.4 | 2.9 | 1.3 |
| AES-128-GCM seal, 100 B (GB/s) | 1.29 | 2.03 | 1.51 | 1.28 | 0.66 | 0.73 | 0.63 | 0.31 |
| AES-256-GCM seal, 16 KiB (GB/s) | **9.7** | 9.0 | 8.9 | 3.1 | 2.4 | 3.5 | 3.5 | 1.3 |
| ChaCha20-Poly1305 seal, 16 KiB (GB/s) | 1.35 | 2.37 | 2.37 | 1.26 | 1.2 | 1.8 | 1.8 | 0.9 |
| SHA-256, 1 MiB (GB/s) | 0.38 | 3.49 | 3.49 | 3.49 | 0.19 | 0.36 | 0.36 | 0.20 |
| ECDSA P-256 verify (us) | 33 | 26 | 24 | 80 | 89 | 63 | 63 | 190 |
| Ed25519 verify (us) | 57 | 19 | 24 | 19 | 160 | 60 | 43 | 56 |
| RSA-2048 verify (us) | 30 | 10 | 14 | 84 | 59 | 25 | 22 | 227 |
| X25519 key pair + shared secret (us) | 78 | 21 | 19 | 26 | 188 | 76 | 36 | 80 |

| TLS 1.3 client, against the same rustls server | M5: pratique | rustls + ring | rustls + aws-lc-rs | x86-64: pratique | rustls + ring | rustls + aws-lc-rs |
|---|---:|---:|---:|---:|---:|---:|
| full handshake, median wall time (ms) | 0.32 | 0.18 | 0.18 | 0.9 to 1.2 | 0.6 to 0.7 | 0.7 to 1.0 |
| full handshake, median client CPU (ms) | 0.25 | 0.11 | 0.11 | 0.7 to 0.9 | 0.37 to 0.47 | 0.40 to 0.59 |
| download, AES-128-GCM (GB/s) | 3.2 | 3.9 (5.0 once) | 3.9 | 0.9 to 1.1 | 0.8 to 1.4 | 1.0 to 1.1 |
| the same: GB per second of client CPU | **5.1** | 4.1 (5.0 once) | 4.1 | 1.3 to 1.5 | 1.1 to 1.6 | 1.2 to 1.3 |
| download, ChaCha20-Poly1305 (GB/s) | 1.22 | 1.63 | 1.63 | about 0.7 | about 0.7 | 0.7 to 0.9 |

After B-103 (2026-10-08, the same machines and VMs, two runs of the primitives, one of TLS; a range where the two runs
differed):

| | M5: pratique | ring | aws-lc-rs | RustCrypto | x86-64: pratique | ring | aws-lc-rs | RustCrypto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AES-128-GCM seal, 16 KiB (GB/s) | **11.7** | 9.7 to 9.9 | 9.5 to 9.6 | 3.7 | 4.0 to 4.2 | 4.9 to 5.0 | 4.8 to 5.0 | 1.5 |
| AES-128-GCM seal, 1 KiB (GB/s) | 7.7 | 7.5 to 8.1 | 6.9 | 3.4 | 3.3 to 3.4 | 3.4 | 3.0 | 1.3 |
| AES-128-GCM seal, 100 B (GB/s) | 1.68 | 1.86 to 2.13 | 1.51 | 1.28 | **1.10** | 0.70 | 0.62 | 0.31 |
| AES-256-GCM seal, 16 KiB (GB/s) | **9.9** | 9.2 to 9.3 | 9.1 to 9.2 | 3.6 | 3.0 to 3.1 | 3.6 to 3.7 | 3.5 to 3.6 | 1.3 |
| ChaCha20-Poly1305 seal, 16 KiB (GB/s) | **2.68** | 2.37 | 2.37 | 1.26 | 1.2 | 1.8 to 1.9 | 1.9 | 1.0 |
| ChaCha20-Poly1305 seal, 1 KiB (GB/s) | 1.85 | 1.87 to 1.88 | 1.82 | 1.07 | 1.0 | 1.4 to 1.5 | 1.4 | 0.4 |
| ChaCha20-Poly1305 seal, 100 B (MB/s) | 514 | 667 | 602 to 605 | 305 to 308 | 322 to 327 | 519 to 520 | 467 to 469 | 57 to 58 |
| SHA-256, 1 MiB (GB/s) | 3.49 | 3.49 | 3.49 | 3.49 | 0.20 | 0.37 | 0.35 to 0.36 | 0.20 |
| ECDSA P-256 verify (us) | 33 | 26 | 24 | 80 to 81 | 89 to 93 | 63 to 65 | 61 | 187 to 189 |
| Ed25519 verify (us) | 24 to 30 | 18 | 24 | 23 to 25 | 74 to 75 | 53 | 42 to 43 | 51 |
| RSA-2048 verify (us) | 13.8 | 10.1 | 13.5 | 81 | 39 to 40 | 23 to 24 | 22 | 215 to 226 |
| X25519 key pair + shared secret (us) | 27 | 21 | 19 | 26 | 78 to 79 | 73 to 75 | 36 to 37 | 78 to 80 |

| TLS 1.3 client, against the same rustls server | M5: pratique | rustls + ring | rustls + aws-lc-rs | x86-64: pratique | rustls + ring | rustls + aws-lc-rs |
|---|---:|---:|---:|---:|---:|---:|
| full handshake, median wall time (ms) | 0.23 | 0.18 | 0.18 | 0.87 | 0.67 | 0.73 |
| full handshake, median client CPU (ms) | 0.16 | 0.11 | 0.10 | 0.59 | 0.45 | 0.45 |
| download, AES-128-GCM (GB/s) | 3.3 | 4.0 | 3.9 | 1.06 | 1.08 | 1.01 |
| the same: GB per second of client CPU | **5.1** | 4.1 | 4.1 | 1.6 | 1.5 | 1.3 |
| download, ChaCha20-Poly1305 (GB/s) | 1.50 | 1.66 | 1.65 | 0.70 | 0.80 | 0.94 |
| the same: GB per second of client CPU | **2.0** | 1.7 | 1.7 | 0.72 | 0.96 | 1.0 |

After B-104 (2026-10-08, the same machines and VMs, two runs of the primitives and the handshakes, one of the downloads on the
M5; a range where the two runs differed):

| | M5: pratique | ring | aws-lc-rs | RustCrypto | x86-64: pratique | ring | aws-lc-rs | RustCrypto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AES-128-GCM seal, 16 KiB (GB/s) | **11.7** | 9.8 to 9.9 | 9.7 | 3.2 | 4.4 to 4.5 | 4.7 to 5.0 | 4.9 to 5.0 | 1.5 |
| AES-128-GCM seal, 1 KiB (GB/s) | 7.8 | 7.9 to 8.0 | 6.9 | 3.0 | **3.7** | 3.4 | 3.0 | 1.3 |
| AES-128-GCM seal, 100 B (GB/s) | 1.69 | 1.98 to 2.07 | 1.51 | 1.28 | **1.13** | 0.70 to 0.72 | 0.62 | 0.31 |
| AES-256-GCM seal, 16 KiB (GB/s) | **9.8 to 9.9** | 9.2 to 9.3 | 9.2 | 3.1 | 3.2 to 3.3 | 3.6 | 3.6 | 1.3 |
| ChaCha20-Poly1305 seal, 16 KiB (GB/s) | **2.69** | 2.38 | 2.37 to 2.38 | 1.27 | 1.36 to 1.39 | 1.83 to 1.84 | 1.84 to 1.86 | 1.03 to 1.05 |
| ChaCha20-Poly1305 seal, 1 KiB (GB/s) | 1.86 | 1.88 | 1.82 | 1.07 | 1.07 to 1.09 | 1.46 to 1.47 | 1.41 | 0.40 |
| ChaCha20-Poly1305 seal, 100 B (MB/s) | 513 to 514 | 671 | 603 to 606 | 306 to 308 | 328 | 521 to 525 | 457 to 472 | 59 to 60 |
| SHA-256, 1 MiB (GB/s) | 3.50 | 3.50 | 3.50 | 3.50 | 0.21 | 0.38 | 0.37 to 0.38 | 0.20 |
| ECDSA P-256 verify (us) | 30 | 26 | 24 | 79 to 80 | 73 | 62 to 63 | 61 | 186 to 193 |
| Ed25519 verify (us) | 22.6 to 22.7 | 18.4 to 18.5 | 24 | 18.8 to 18.9 | 62 to 63 | 53 | 42 to 43 | 50 to 51 |
| RSA-2048 verify (us) | 13.7 | 10.0 | 13.5 | 81 to 82 | 39 | 23 to 24 | 21 to 22 | 213 to 217 |
| X25519 key pair + shared secret (us) | 24.5 | 20.8 | 18.9 | 25.8 | **62 to 63** | 73 to 74 | 36 | 79 |

| TLS 1.3 client, against the same rustls server | M5: pratique | rustls + ring | rustls + aws-lc-rs | x86-64: pratique | rustls + ring | rustls + aws-lc-rs |
|---|---:|---:|---:|---:|---:|---:|
| full handshake, median wall time (ms) | 0.22 | 0.18 | 0.18 | 0.70 to 0.81 | 0.56 to 0.58 | 0.56 to 0.63 |
| full handshake, median client CPU (ms) | 0.142 to 0.144 | 0.107 to 0.108 | 0.103 to 0.104 | 0.46 to 0.48 | 0.35 to 0.36 | 0.33 to 0.37 |
| download, AES-128-GCM (GB/s) | 3.3 | 3.9 | 3.9 | 1.0 to 1.1 | 1.2 to 1.5 | 0.9 to 1.4 |
| the same: GB per second of client CPU | **5.2** | 4.1 | 4.1 | 1.7 | 1.6 | 1.2 to 1.6 |
| download, ChaCha20-Poly1305 (GB/s) | 1.50 | 1.65 | 1.66 | 0.78 to 0.80 | 0.74 to 0.96 | 0.74 |
| the same: GB per second of client CPU | **2.0** | 1.7 | 1.7 | 0.81 to 0.82 | 0.89 to 1.05 | 0.78 to 0.82 |

The same on the same M5 under macOS itself, before B-103 (2026-10-08, `cargo run --release`), which is what an application
there gets; it has not been run natively since. aws-lc-rs is much faster natively than in the VM (12.3 against 9.5 GB/s at
16 KiB), and so is the loopback download:

| macOS, M5 Max | pratique | ring | aws-lc-rs | RustCrypto |
|---|---:|---:|---:|---:|
| AES-128-GCM seal, 16 KiB / 1 KiB / 100 B (GB/s) | **12.8** / **8.1** / 1.26 | 9.5 / 7.5 / **1.99** | 12.3 / 7.9 / 1.54 | 4.8 / 4.2 / 1.46 |
| AES-256-GCM seal, 16 KiB / 1 KiB / 100 B (GB/s) | **10.5** / 7.1 / 1.17 | 8.9 / **7.4** / **2.11** | 10.4 / 7.2 / 1.48 | 4.5 / 4.1 / 1.36 |
| ChaCha20-Poly1305 seal, 16 KiB / 100 B (GB/s) | 1.37 / 0.32 | **2.35** / **0.68** | 2.35 / 0.61 | 1.24 / 0.26 |
| SHA-256, 1 MiB (GB/s) | 0.47 | 3.53 | 3.53 | 3.53 |
| ECDSA P-256 / Ed25519 / RSA-2048 verify (us) | 33 / 52 / 29 | 26 / 18 / 10 | **24** / **16** / **8** | 80 / 18 / 79 |
| X25519 key pair + shared secret (us) | 73 | 22 | **16** | 25 |

| macOS, M5 Max, TLS 1.3 client | pratique | rustls + ring | rustls + aws-lc-rs |
|---|---:|---:|---:|
| full handshake, median wall time / client CPU (ms) | 0.38 / 0.26 | 0.20 / 0.12 | 0.20 / 0.12 |
| download, AES-128-GCM (GB/s) / GB per client CPU second | 3.9 / **4.7** | 4.1 / 4.1 | 4.0 / 4.1 |
| download, AES-256-GCM (GB/s) / GB per client CPU second | 3.7 / **4.3** | 3.8 / 3.8 | 3.7 / 3.7 |
| download, ChaCha20-Poly1305 (GB/s) | 1.2 | 1.7 | 1.7 |

How to read it (after B-104):

* **Bulk AES-GCM:** on Apple silicon pratique is the fastest of the four at 16 KiB (11.7 against 9.7 to 9.9 GB/s in the
  VM) and level at 1 KiB, and as a TLS client it downloads on about a fifth less client CPU per byte than rustls. On x86-64
  the GHASH reduction by two carry-less products (B-104) took 16 KiB to 4.4 to 4.5 GB/s against ring's 4.7 to 5.0 (their
  kernels are hand-written assembly; this one is intrinsics), and puts it ahead of both at 1 KiB (3.7 against 3.4 and 3.0) and
  1.6 to 1.8 times faster at 100 B. Against RustCrypto, the other pure-Rust choice, it is 2.6 to 3.7 times faster (1.3 times
  at 100 B on the M5).
* **Short messages:** at 100 B, AES-GCM is ahead of aws-lc-rs and RustCrypto on the M5 and behind ring (1.69 against 2.0 to
  2.1 GB/s). What is left of that is the switch to data-independent timing on entry and back on exit, about 30 ns a call,
  which ring does not make (B-99 makes it on purpose); since B-104 the TLS and QUIC layers make it once for all the records
  or packets of a call, but a caller of the AEAD itself still makes it each time.
* **Handshakes** cost 1.3 to 1.4 times rustls's client CPU (0.14 against 0.10 to 0.11 ms in the M5 VM, 0.16 before B-104;
  0.46 to 0.48 against 0.33 to 0.37 on x86-64, 0.59 before). B-104 profiled one: what was not cryptography is now about a
  tenth of the client's instructions. On x86-64 X25519 is now quicker than ring's (62 against 73 to 74 us); ECDSA P-256
  verification is the largest public-key cost left in these handshakes (1.2 to 1.3 times both), and SHA-256, which this VM
  runs without SHA extensions, is about a seventh of a handshake's instructions there.
* **Signatures:** Ed25519 verification is quicker than aws-lc-rs's on the M5 (22.7 against 24 us) and RSA-2048 level with
  it; both are 1.2 to 1.4 times ring there; on x86-64, 1.2 to 1.8 times both. Against RustCrypto, ECDSA and RSA are 2.6 to 6
  times faster; Ed25519 is 1.2 times slower on both machines.
* **SHA-256** runs on the ARMv8 SHA-2 instructions where the CPU has them, level with the others (3.50 GB/s); this x86-64
  VM has no SHA extensions (the SHA-NI code is checked under emulation), where ring's vectorised message schedule is 1.8
  times faster.
* **ChaCha20-Poly1305** is the fastest of the four on Apple silicon at 16 KiB (2.69 against 2.38 GB/s) and level at 1 KiB,
  behind at 100 B. On x86-64 B-104's AVX2 Poly1305 (from 2 KiB) and keystream took 16 KiB from 1.2 to 1.36 to 1.39 GB/s,
  still 1.3 times slower than ring and aws-lc-rs: this Cascade Lake lowers its clock while 256-bit multiplications run, and
  the AVX-512 keystream is not used on it for the same reason.

B-103 and B-104 in BACKLOG.md have what each change did; what is left, in the order it would pay off, is B-106.

## Building an application for speed

Measured on the same VM with this crate's benchmarks, three alternating runs of each build, medians compared:

| Build settings (in the application's `Cargo.toml` or `RUSTFLAGS`) | Effect here |
|---|---|
| `[profile.release]` `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` | no speed gained (all 42 figures: 0.95 times, within the noise; the ChaCha20-Poly1305 figures 12 to 16 percent lower); binaries 21 to 27 percent smaller |
| `-C target-cpu=native` | 1.06 times over all the primitives: ChaCha20-Poly1305 1.17 to 1.41 times, P-256 verification 1.16, but SHA-256 0.80; the binary then needs a CPU with everything the build machine's has |

So the crate does not need special settings: the default release profile is what it is tuned with, and the vector code
(AES-NI, PCLMULQDQ, AVX2, AVX-512, the ARMv8 AES and PMULL instructions) is chosen at run time whatever the target. LTO
and one codegen unit are worth having for the size of the binary. `panic = "abort"` changes what a panic does: a panic in a
task on `asyncio::Pool` (the thread-backed futures) ends the process instead of coming back as `TaskError::Panicked`, and a
panic in one of the client's own threads (an HTTP/2 or HTTP/3 connection's reader) ends the process instead of that
thread, and with it that connection; an application that would rather stop than go on after a bug may want exactly that.

## Before optimizing: profile

Every change to a hot path in this crate is measured with the benchmarks above, alternating the old build and the new,
and starts from a profile, because the first guess about where the time goes has been wrong more often than right here
(B-57: four blocks of Poly1305 at a time gained 7 percent, where its instruction count, not its chain of dependencies, was
the limit; B-49: a dedicated squaring was slower on the curves than the multiplication it replaced).

* Linux: `perf record -g ./target/release/examples/bench_net --quick` and `perf report`, or `cargo flamegraph --example
  bench_net --features server -- --quick` (`cargo install flamegraph`). Build with symbols for it:
  `CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --features server --example bench_net`.
* macOS: Instruments' Time Profiler (`xcrun xctrace record --template 'Time Profiler' --launch -- ./target/release/examples/bench`),
  or `samply record ./target/release/examples/bench` (`cargo install samply`).
* Against a server that is the limit, a client that does less shows it as more waiting, not as less CPU: B-87 saved 10 ms of user
  time on a 100 MB download from Go's server and spent as much more in system time, as the client found the socket empty more often.
  To see the client's own cost, put it on the server's core: `CPUS=0 bash tools/bench_h2.sh 9 stream` (the server is pinned to core
  0), where the time is the two processes' CPU added up and a cheaper client is a faster run.
* For a function of a few hundred instructions, read what the compiler made of it (`objdump -d -M intel`, or
  `cargo asm` from `cargo install cargo-show-asm`): that is how B-57 found that its AVX2 Poly1305 was limited by two
  execution ports, not by its code, and B-104 that the X25519 field multiplied 128 bits by 128 where 64 by 64 does (38
  multiply instructions for 25 products), that the compiler had turned the AVX2 Poly1305's 32-bit products into 64-bit ones,
  and that it had doubled the shuffles of the AVX2 ChaCha20.
* For where a handshake's time goes, count instructions: `valgrind --tool=callgrind ./target/release/compare prof 40` in
  `bench/compare`, then `callgrind_annotate --inclusive=yes` (B-104 found the transcript hashed again from its first byte at
  each of six points, a seventh of a client's instructions; a server thread runs in the same process, under its own names).
