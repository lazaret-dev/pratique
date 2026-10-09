//! Ed25519 signing (RFC 8032, section 5.1.6), in constant time (B-109).
//!
//! The secrets are the scalar a (from the key's seed) and the nonce r (from the seed's other half and the message);
//! both stay out of every branch and memory address:
//!
//! * \[r\]B and \[a\]B are the fixed-base multiplication of `x25519_base` (ref10's table of multiples of B, every entry of
//!   a row read at each step and the one needed kept with masks), not the verifier's variable-time double-and-add,
//!   which is what this module used until B-109 (it was for the test server only);
//! * r from its 64-byte hash, and S = r + k a, are computed modulo L by `ct_mod` (Montgomery products, conditional
//!   subtractions by mask), not by the verifier's bit-at-a-time reduction, which branches on the value;
//! * encoding \[r\]B is one inversion by a fixed chain and a canonical reduction without branches.
//!
//! Signing is deterministic, as RFC 8032 says (the same key and message give the same signature), so no randomness is
//! needed and none is used. The data-independent-timing mode of ARM (`crypto::dit`) is held while the secrets are in
//! use. The verifier in `ed25519.rs` is the check: every test signature here is verified with it, and the signatures
//! must equal RFC 8032's and those OpenSSL makes for the same keys; `crypto::timing` checks the timing.

use super::ct_mod::{self, Modulus};
use super::dit::Dit;
use super::ed25519::Point;
use super::sha2::{Hash, Sha512};
use super::x25519_base::mul_base;
use crate::zeroize::{Zeroize, Zeroizing};
use std::sync::OnceLock;

/// The order of the base point, L = 2^252 + 27742317777372353535851937790883648493.
fn order() -> &'static Modulus<4> {
    static L: OnceLock<Modulus<4>> = OnceLock::new();
    L.get_or_init(|| Modulus::from_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
}

/// An Ed25519 private key: the 32-byte seed RFC 8032 calls the private key, expanded once into the scalar and the
/// nonce prefix, with the public key.
#[derive(Clone)]
pub struct Ed25519SigningKey {
    seed: Zeroizing<[u8; 32]>,
    /// the clamped scalar a, little-endian
    a: Zeroizing<[u8; 32]>,
    prefix: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl std::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519SigningKey(public {})", crate::util::hex(&self.public))
    }
}

impl Ed25519SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Ed25519SigningKey {
        let _dit = Dit::on(); // data-independent timing while the secrets are in use (crypto::dit)
        let mut digest = Zeroizing::new(Sha512::digest(seed));
        let mut a = Zeroizing::new([0u8; 32]);
        let mut prefix = Zeroizing::new([0u8; 32]);
        a.copy_from_slice(&digest[..32]);
        prefix.copy_from_slice(&digest[32..]);
        digest.zeroize();
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let mut point = mul_base(&a);
        let public = point.encode();
        wipe(&mut point);
        Ed25519SigningKey { seed: Zeroizing::new(*seed), a, prefix, public }
    }

    /// A new random key.
    pub fn generate() -> std::io::Result<Ed25519SigningKey> {
        let mut seed = Zeroizing::new([0u8; 32]);
        super::rand::fill(&mut seed[..])?;
        Ok(Ed25519SigningKey::from_seed(&seed))
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// A key made from the scalar and the prefix directly (no seed): for the timing tests, which choose the scalar.
    #[cfg(test)]
    pub(crate) fn from_expanded(a: [u8; 32], prefix: [u8; 32]) -> Ed25519SigningKey {
        assert!(a[31] < 128, "a scalar below 2^255");
        let public = mul_base(&a).encode();
        Ed25519SigningKey { seed: Zeroizing::new([0u8; 32]), a: Zeroizing::new(a), prefix: Zeroizing::new(prefix), public }
    }

    /// The signature (64 bytes) of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let _dit = Dit::on();
        let l = order();
        // r = SHA-512(prefix || M) mod L
        let mut h = Sha512::new();
        h.update(&self.prefix[..]);
        h.update(message);
        let mut r = reduce64(l, &Zeroizing::new(h.finalize()));
        let mut r_bytes = Zeroizing::new([0u8; 32]);
        r_bytes.copy_from_slice(&ct_mod::limbs_to_le(&r, 32));
        // R = [r]B (r < L < 2^253, as the table multiplication needs)
        let mut point = mul_base(&r_bytes);
        let big_r = point.encode();
        wipe(&mut point);
        // k = SHA-512(R || A || M) mod L (public)
        let mut h = Sha512::new();
        h.update(&big_r);
        h.update(&self.public);
        h.update(message);
        let k = reduce64(l, &h.finalize());
        // S = (r + k a) mod L in the Montgomery domain; a (below 2^255) is reduced on the way in
        let mut a = ct_mod::limbs_from_le::<4>(&self.a[..]);
        let mut a_m = l.to_mont(&a);
        let mut r_m = l.to_mont(&r);
        let mut s_m = l.add(&r_m, &l.mul(&l.to_mont(&k), &a_m));
        let mut s = l.from_mont(&s_m);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&ct_mod::limbs_to_le(&s, 32));
        for v in [&mut r, &mut a, &mut a_m, &mut r_m, &mut s_m, &mut s] {
            v.zeroize();
        }
        signature
    }
}

/// Overwrites a point's coordinates (a multiple of B by a secret is as secret as the scalar until it is encoded).
fn wipe(p: &mut Point) {
    for c in [&mut p.x, &mut p.y, &mut p.z, &mut p.t] {
        c.0.zeroize();
    }
}

/// A 64-byte little-endian number modulo L.
fn reduce64(l: &Modulus<4>, wide: &[u8]) -> [u64; 4] {
    let lo = ct_mod::limbs_from_le::<4>(&wide[..32]);
    let hi = ct_mod::limbs_from_le::<4>(&wide[32..64]);
    l.reduce_wide(&lo, &hi)
}

/// The public key for a 32-byte secret seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    *Ed25519SigningKey::from_seed(seed).public_key()
}

/// The signature (64 bytes) of `message` under the key with this secret seed.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    Ed25519SigningKey::from_seed(seed).sign(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519;
    use crate::util::{hex, unhex};

    fn seed(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn rfc8032_section_7_1_test_1_and_2() {
        // TEST 1: empty message
        let s1 = seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        assert_eq!(hex(&public_key(&s1)), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(
            hex(&sign(&s1, b"")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        // TEST 2: one byte
        let s2 = seed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        assert_eq!(hex(&public_key(&s2)), "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        assert_eq!(
            hex(&sign(&s2, &[0x72])),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
    }

    #[test]
    fn rfc8032_section_7_1_test_3() {
        let s3 = seed("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        assert_eq!(hex(&public_key(&s3)), "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        assert_eq!(
            hex(&sign(&s3, &unhex("af82"))),
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        );
    }

    /// Signatures OpenSSL made (Python `cryptography` 50), for seeds all zero, all 0xff, all 0x80 and random ones,
    /// messages of 0 to 200 bytes: (seed, public key, message, signature).
    const OPENSSL: [(&str, &str, &str, &str); 24] = [
        ("0000000000000000000000000000000000000000000000000000000000000000", "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", "", "8f895b3cafe2c9506039d0e2a66382568004674fe8d237785092e40d6aaf483e4fc60168705f31f101596138ce21aa357c0d32a064f423dc3ee4aa3abf53f803"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5", "65", "fccf14093df88e56132557de0849a8bd643a8bd534c2959237e98ff3518d4148cde9c50f3e33a5eca63e4be330634d6cc80afa569938a5c13728d184df853108"),
        ("8080808080808080808080808080808080808080808080808080808080808080", "e5687b6d11ccfb632abbafe844f8f1693d160aa582156ed66eea38ab5e7d1e12", "a6e69c131b1b5a81e25f198a467b0880c8ab4559d13cc58badf59d05fec0c73d5f96668935256e11e5beb3a87c247e36e5c0c6d4503a522503a6ec851f64f7", "9bcddb0435ebfb380ab352a33192e7b7df67d9c93077417f9e4bd058a32af4ec309a151fb0e36aced1d6494fd21ab5a168045993103164442cc9c3480d21f006"),
        ("f2982266f9aab17857ae10db76979c47c17ad59f8710a53503248d81bb959a0c", "2ad3c26159f93f2c10d9117793c6720d8acf4eb2c8a4436d3317f0cd9add138d", "8905b96be98e6afc64a58cf9c464fad00f80fb16a9b9e3cfc2eedc460b0c48c2cb4fd0d5e2b5700e2cc5e55cbf393d567a5e3fa6342f38f32ca0dd22bd9199f3", "891b5a8fa8aadd34308b96d71c9ff39d887e7f2c4212161267550a01fc28056772698dfb7e79e2d0f4147a3f90c031195b7623360b39de4ee784508d50a7ed03"),
        ("64bcee37b04b6e60e215cd48fc1b3f2d441045332eff0334344079b963f47c11", "c7262c1da0e3ca3e3552de1942d9eafd0e7037cb63797aa78f1792f98b08338a", "9c0531ecee8cb3aa4fedb4e26138ea27ed9f0d530ce5fb337d1d45c02d09be9dfc6f6e0aa64cf9c585d46baf1fccd3fd0e6bdf0af2745a0f4920da5822510a985e", "859fe469353fe355180e4aa6eae020a598677dc81cbd0077df1b4d0e357cb898077d0672f57370b7d9c8d90aa626c42bda9e0e4393926f6639d3cd5627f0d209"),
        ("87d82b5406f0b3ca94f86964a54743dda29922257d440dac912df207132e8dbc", "eb6dfb57b4380d8edc0ed591602faad78a20414255d953d985414c532bc31499", "c0ee51fc4260d96e82d0941c3ae6f0d47f662e32b01967541e6f940b5064965b94a3c6a1595a55a2191ac90185c956b9c9f35bde7f58c423116d203ce765ca0794d39105ceb94356a48c064bc72e15fb4393ef83de6fdeb96cadde68e1770defcfe89bea3f8ffe3695801477dca316dcb3bc263627f4282ae48be5f8274bf77ba6fa3621b069e4ee2c451d3c33274b25f254eff417f6190efaa6c200da27af6171b018b8ed8b411a378967320badf520da21918df4e5f04e8b4cc7ac33df80aa1139f9e54f56290e", "db93bac24855a1cd931c59e3c49ec27d778b39f7067046c323798c1f2ee87b65a62f9ab19f5ee3dcf7ef6238541f02c26cfb0e7501000e59023fa66a18c21504"),
        ("2e6a73e6640eb294421b8d1a7cf69e8cfce0bbd8b337b696f8252eb32d620b67", "d4d92c48ed8cb08e3abad52a2156997601cd861a4372f4b75eadb384479fcfc7", "", "49156413d752ee454cfe1787348c4ea2cf743dd7079a4e56ccca5e0368f37ba07063c836b878a5484ffeed269696bfb50e8489b487bae7c789a9958704a16506"),
        ("e0e8dd3cf08c75f6139e7361f2ffe8abd77917d63f01d57aa68e0db11bc12ffa", "848acdef9ab0f330b2564facb63dd1ea5fe65125e1c36d11d8e11fa8d74d864b", "b0", "7bc0fe5adc569d017bee145ed51094b46e284616e95b9e2186d23f50552fca9f0b7a6c5eea88c05116792ba55fdbadb0465d8192b5f41a67ec98323e7656d404"),
        ("3ca092187cc8271319e54192aeb68fc91ee131ead38fabd8071040c0ab439d06", "65063490c0b3e8b955b817a730e9fdd6b9506f15db13f35548de7bf3ed6d763b", "10ae46390690115e8b31222f4a3f47a300a1656876409cb2a0e919c7f531c3dca86411b090ffff7050c91469d1fa1dcf1b8fbdf078577ef19dc88f69d89f2c", "52238006659748580b76ad5a27db0a60d3f3ad886d7c28bf1150534e94c64a9bde36002ec87b4b29d699b16ee4d566a5738f941a46d40aa85b3225e471cba304"),
        ("a4038d19c8ea7fca4c7c834d5a12ff44f06de716388a809eac4a0bdd07923c62", "0ec0e2672e1f110381c569dbd51678ee4934cdedeb9040545e54ca9b1af60956", "fe3a84d5a28c8ea0ab514ab66fa1959564d3a8013e5273dd9366d6fba152518bcb5d7577f495eef6c920da08611ba4cde5ef7acc3e9713aba231934195123961", "93554a466deb59c56a1124f4f6926f31c42ca4f946b202c1d44ffa35faea2cfa89dda2eae7f64b3e102223b8776265b11cd43c067dca8e440f6196a139a8ff08"),
        ("8e25376df6595b9179e1d459dc9be691b6a1a07ebfed3f0dd4acb1b82db6c3a7", "91a6303ecea6bb4f7814da9452500da33d6d03940cce1414d3b719cfcccd6cfd", "c61852632437b0ead2de6ab476b5f36088b582e5babe92902bbbedc02bcefb4220262b5942bbbc9e31cf16ea760c8db0340cefbada258ea575799e94f55d18de0a", "e1f9664130aead70ceadb4034c0856d96b6df9f44be4681f7a02e3c0bd65e52cbbfbc89dda315c543d771943f9941cd475c39a2bbadeecde537eecdbe3aee809"),
        ("cd396c6f2c50eb4ab5282b585e041d5420d02ced4fc9c2a8a9474cfbd9ae0a1c", "e16f5baba1ec8306ecf2b4ec633205566db7bb660365e261fc811c9fdd10e3e4", "c48a9892e537eae5f6b179879d214798889974632b8a778f4d91f7659ea286ef72f491dd73b814066d0fd2c22065b76cc4acf1efad12fd1548d99d5d0029a6c9abe0b2ec63402d347ae9e2fe25ddbc1494186f6b50475424a2c5c97666cb03f3cf8b0138513cf6138880a6b058d9a54b9f44132e7ca1748da2a2834ee454facf363bafed98527b4f32e5da55ab9aae561cc3501ee7907887ef704446b199d2953d17a663a5395fc81f44f6f0d54c449e90c6c8d55bd0e37b08b9b73f943d7950da3f4102978f6140", "cce6c47f371d53d547971a84252656e2787073ca6f69d0f6dec83781d36827ef7621d826956fe994c17f850a2fb098b2638353c728b9b3a0286723405d0d8b09"),
        ("c1f0ac945c5befbc8358015477089acce4e2273f721b3e659138baff82775bf0", "37b35644af093064f4dd11f093170ce31f06a46cb21522b1b37e147afff4cb62", "", "a8345856b7da0c21cba03bb10b037abb50fe994aac9c9e7864d54320aff3d730c75c9b09163056aeadcf68fb27430a6993ff3c6fc919206322ac650e5e88d508"),
        ("1521ccd9daf07c169e2a1f9ea993ff4d71471e70bdb65befc217bfaa2f9b8b80", "2914b3ec695c4ac7d754336c81cbe580baf6658942f91a9beb738db7777e4154", "28", "4d77c85c0e7e217780467d0fcfa90eb618b82469e987058acf5f04876fb8a9f42ef959914ca3f98bfc8a994813e42d0f67cc98258de54f47f0ac51417e38f30b"),
        ("059e061f192ab126593316efa4799174f82b7d00c6be333aa5be0e2d909d6d8c", "ffe7d21da168394cdc4c17bb33c9facb87eff37c0f5c86625d2de4d25dce7620", "1a107bf1009d54a13876cc1c7290883e9db89579e22d74b798203dee5f1076f175ef342fdea7cec0c1bb98bb87766107ca38336e05730e610b34dee5665fab", "228319745d87a29f0830a0c295b7e1ea441a8cce071077fac644bc6cb2c89cca2687ca7534f982c57affd022e35ba6034e3ce25ca73e1ad5d975e2eb6347340f"),
        ("728d1943bfaff4679107d71b7e5773316e1f721b960cad2027bba23db01135ff", "44de61c9ac88b3a5f63a85e96f366950ce83d64aaaad7c4dcabbd9a17bc576bc", "69838e4a3a694a1605225785cdcd121e061be4b572a199eab172f340c009aa4f6e1d71a572286afcb24d1b8d7de1fe9006bddd373395ac4a774664ceeff9d4ad", "2ab1dced5733a6637c304eb4aabe8420a70153c956c289516a72f6a7afef2aa35b2bcabb0a84c1db4a59ef0e049507c49cdad071a887610fdade9caf89fd4d09"),
        ("f93645e0a7b562d5c4b7b95974bfd68f9ca9963c81694090bfe5d9f122958099", "7274c1ac6e5fb80474be5c789dd7425ff260689f255f543050ff1f1c630e5ba2", "5c105cb3de533806be1d9207c2c99d6c3b4ac098937b198b4a2205fd2c8eb6f14227eb56e53c83b2ac0d7ce9e67eeb62fa420fcffacf205aaa55f579a775f6af2b", "d018644ad7aead9d28bd4a46fbd8804eca05089982eaae752eaad59270c6ce8e76a21ff102cd19a9843f706aad0726f3fef95be60708746397445beaf4e82500"),
        ("e42ba063d525dfd6c3ec03ad130d7e001f3276b21bee2affb128bcef708696d4", "382d96ad49dbe1ef9c02010a359dcc43753166a69f7fc218f6d8d7ecad180617", "846b8e3408b4f4fb2e2429d719bded0ef8785a32d110a0459cb1d7f83abd945dce1f5a77282df722073d5c4d48fc106277401ce0e11eba27e9a0076a3efbb0bc73edd6c42ba87a50ec3c117a2b90b9a57e36f27ece7a8a6a06b11a4ebe09fe729d12c39807e1e746a36c274cfab45b781582b8b09470b3af6301b75c63850c7559773c16c0f3400f38d3f426cea7176b237d04344f6640ad482daf2d6a9267a86b28f0df99c727c655d4fb2a0ce9ae4d07350e821e8aafc2312e2fdb87e6a0e3339a5f2495622f39", "838526115d8265738c4f3d0ee07614a12edccdc79acdd65638453ee638195d0fcdb347b337b0a48154c1a709ddf2786b32c8f4def71efab30accd2dc38596809"),
        ("36c9453569921db526d204cc3097cc351884fdce4846e418604509c4aeabf34b", "d8e2b7423e70357a7ced16a09c738174960e709bf39afb523bc8fa63a4be8a07", "", "349d1f78556811751cc91da0ed6c56f73101198fdb6a771d645fe16016146f783b7430d4fa8af9d578afddc1f4b8e5af75c85104edb8bf8cf67d3d8d23ed5b01"),
        ("839cccb6d8f640a61b42442fe3f288a24b8470bc11d7e6130af9a0d10014e9b6", "2ca4dec18113f2d51c09f191afeb78e01906109c9000c095ad379463e361bfd5", "09", "9186b1e1a28e1ce49cd6ce33bba95cd9f946bd2eca66293ce8b7cc23e5c1b2957757d23401089d7343844490024e934115422c44f8de42683e2a1288097b8c05"),
        ("c2fdf0c8b077c43632d83ce7a5ed5bb32c2f6a0105a7a263f75983b203332881", "0219f6041c67d453e267496f5f3135176d2ee3c61c8621473a63029b81fc3bc8", "3fb53d957613a21dbb4632d1873e603f233a52eacaeaac5999e2bf11a956660a5a40a221c56f3b1fc85f09b8dbac639046fddb5aa38720c4cdf19703dae9a1", "e7fe100143b1007e80bf7af9717886ed957be8be97886da0060c8ffb3ed170ec7f84604b5d9fd9703ab75a80785986a62c1578dee923a573ed3fa1ddc3202803"),
        ("98e87b29da10d39aa672ad95583e573b588d4a4628b1fa49506afd8b41c0a3e0", "38922f235eb888e35ef0bc61daf8561b80310c320d520255bb5926192e936e1b", "88b7a08fdd3e99d51e3af5a85f8501bc45193e3aa1a8ade93909affe07d52b73864b393ec61b22674c09c6d897c44eed2309a32ac82c9ccfa3ca627e7b1c0d8e", "506f0c8eb47852b2ac588c8fb657a08d153afcfe446f00ca210602ca73e978aac41f4a376ffaed9ee31de188fc9da4258995656ca6cc3a605a707fb05b08de09"),
        ("677b6412af3e829725ea06f6b828b30197c3ffc0ce2417bc508430ca257a88b3", "db6b1d9ac1b8372dd2f16f45fd3efea37daf7f11c434994c7ef1203f5656246e", "1df532b59e106dc199d9c6be6afef7dd4be99ab80526971cddef39dc36fedbe4a368163155588544b8d05c0657afe95b78991f7cc26771499696d92940f3d01a74", "265fe839c1d2594dfb4a7da1ac75544582006f4f10b4540ecb501a077419227709934735d44e94a2f8001f2855ded767f738c576d0f9a84600fc7721be9c7e02"),
        ("a577326b694db0b39d95e503d8f3509666c7b1d8f5592f5e753870a68aef4854", "41559b3cfe061bb884b3cd5b85a39785cd47446b28ce82f410d6a06a3bbde79e", "d1b532a4a314a5394178b165c9af4258e1c09e3f51b63fbd5ce0151ed6e62a61ae579e5cd885950014859d557e3f3c5b53bd1f5bc407334a33aec88e3239796783a15ecb48c5e88d1bad69d7899aebb1e6cbe0774cd8fcdf2174e65495518f4488ecb9d2de1c1070356a3424b54e30c02b96ca13daa8ccd87e8b1bc77811e0e1cc049088bd9ec3f59d891e2377883dc381b5443fd17d77fe5055cc30b7a528cf2495232704df5aeb02fecd3a0f96b92446dc98d181712b37f316ba0c83418825eff015210c77bfdd", "e3bfa85d4898f3628876f33963b4267eb8959de16fc45ab00a92829bd368e5692cebad7f3f8cc5472696d9e67a20ed2e7daa50a8249cabf52b7eb65c7a03860e"),
    ];

    #[test]
    fn signatures_equal_openssls() {
        for (s, public, message, signature) in OPENSSL {
            let k = Ed25519SigningKey::from_seed(&seed(s));
            assert_eq!(hex(k.public_key()), public, "seed {s}");
            assert_eq!(hex(&k.sign(&unhex(message))), signature, "seed {s}");
        }
    }

    #[test]
    fn what_is_signed_verifies_and_is_deterministic() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..48 {
            let mut s = [0u8; 32];
            for b in s.iter_mut() {
                *b = next() as u8;
            }
            let message: Vec<u8> = (0..(next() % 300) as usize).map(|_| next() as u8).collect();
            let key = Ed25519SigningKey::from_seed(&s);
            let sig = key.sign(&message);
            assert!(ed25519::verify(key.public_key(), &message, &sig), "round {round}");
            assert_eq!(sig, key.sign(&message));
            let mut other = message.clone();
            other.push(0);
            assert!(!ed25519::verify(key.public_key(), &other, &sig), "round {round}");
        }
    }

    #[test]
    fn the_wide_reduction_is_the_verifiers() {
        let mut state = 0x0bad_c0de_dead_beefu64;
        let mut wide = [0u8; 64];
        for round in 0..200 {
            for b in wide.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            if round == 0 {
                wide = [0xff; 64];
            }
            let got = ct_mod::limbs_to_le(&reduce64(order(), &wide), 32);
            assert_eq!(got, ed25519::scalar_reduce(&wide).to_vec(), "round {round}");
        }
    }
}
