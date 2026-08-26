//! The off-circuit model of one `execute` call: its arguments, its witness, and the ledger's
//! answers — plus the four benchmark scenarios.
//!
//! # Provenance
//!
//! Ported from the port crate's own equivalence-gate support — `manager-port/tests/support/model.rs`
//! and `manager-port/tests/execute_differential.rs` (the bar-A scenarios) — with two changes and no
//! third:
//!
//! 1. **minocrab is gone.** 00012's copy imported `minocrab_zkir::v3::{IrType, IrValue}`, which are
//!    re-exports of upstream's own types; this file uses `midnight_zkir_v3::ir_types` directly, so
//!    the harness links no minocrab code at all. That matters: the harness must run BOTH artifacts
//!    through the same path, and nothing on the timing path may come from either compiler's kit.
//! 2. **The EIP-712 constants are inlined.** 00012's scenarios reached them through
//!    `manager_port::eip712`, a crate this harness deliberately does not depend on. The ten
//!    constants are copied byte for byte from `manager-port/src/eip712.rs:48-105`; only the five
//!    the selector-0/1/2/6 scenarios actually use are kept.
//!
//! Everything else — the FAB helpers, the `persistentCommit` recipe, the ECDSA construction, the
//! payload slot order, each scenario's payload and its ledger answers in read order — is verbatim.
//! The fixtures (`self_addr`, `deployment_domain`, `owner_secret`, colours, recipients) keep
//! 00012's exact byte values, so the preimages this harness builds are the preimages the gate
//! ran on.
//!
//! # PROJECT 00020: the tag is now the POST-PR#7 one
//!
//! 00018 benchmarked the pre-PR#7 pair (`main` @ `0eccb66`) and therefore used the old
//! `"aa00005:manager:owner"` separator. This project's artifacts come from `main` @ `713a202`,
//! which carries PR#7's rename, so the tag here is `"aa:manager:owner:v1.0"` (still 21 bytes, so
//! still a `Bytes<21>`). A wrong tag is not a silent failure: `p.account` is supplied as an
//! argument and `authenticatedActionAccount` asserts it equals the circuit's own
//! `ownerCommitment(localOwnerSecret())`, so the artifact refuses the run outright — which is
//! exactly what makes these proofs evidence that the tag is right.
//!
//! Also updated for `713a202`: selector 2's `recipientKind` is 0 (PR#10 refuses a contract
//! recipient on a withdrawal), and selectors 3, 4 and 5 are present for the first time — PR#9's
//! `safeGive` clamp gave them accepted runs.

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::k256;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use midnight_zkir_v3::ir_types::{IrType, IrValue};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::borrow::Cow;

// ---- FAB helpers --------------------------------------------------------------------------------

pub fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

/// `[hi, lo]` slot pair of a `Bytes<32>` — `hi` is byte 31, `lo` the first 31 bytes LE.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the off-circuit
/// `persistentHash`, i.e. the exact three lines `zkir-v3/src/ir_vm.rs` runs for `I::PersistentHash`.
pub fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

/// `pad(32, s)` — Compact's zero-padded 32-byte string literal.
pub fn pad32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    bytes
}

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- the contract's own hashes, off-circuit -----------------------------------------------------

/// `ownerCommitment(sk)` = `persistentCommit<Bytes<21>>("aa:manager:owner:v1.0", sk)` —
/// SHA-256 over `sk ‖ "aa:manager:owner:v1.0"` under `[bytes 32, bytes 21]` (rand THEN value).
pub fn owner_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (hi, lo) = b32_slots(sk);
    let tag = Fr::from_le_bytes(b"aa:manager:owner:v1.0").expect("21 bytes fit");
    fab_sha256(vec![atom(32), atom(21)], &[hi, lo, tag])
}

// ---- the frozen EIP-712 constants ---------------------------------------------------------------
//
// Copied byte for byte from `manager-port/src/eip712.rs`, which copied them from
// `contracts/manager.compact:422-490`. Only the ones selector 1 needs are kept.

/// `accountTag()` — the `evmAccountIdFor` domain separator.
pub const ACCOUNT_TAG: [u8; 32] = [
    0x55, 0xbc, 0x94, 0x0f, 0x83, 0x53, 0x37, 0xf1, 0x22, 0x4c, 0x18, 0x11, 0x10, 0xb2, 0xb7, 0x7f,
    0x57, 0xed, 0x69, 0x4c, 0xae, 0x0c, 0x4b, 0xf8, 0xff, 0x6b, 0xb3, 0xe0, 0x3b, 0xe6, 0xa9, 0x88,
];

/// `domainType()` — `keccak256("EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)")`.
pub const DOMAIN_TYPE: [u8; 32] = [
    0x36, 0xc2, 0x5d, 0xe3, 0xe5, 0x41, 0xd5, 0xd9, 0x70, 0xf6, 0x6e, 0x42, 0x10, 0xd7, 0x28, 0x72,
    0x12, 0x20, 0xff, 0xf5, 0xc0, 0x77, 0xcc, 0x6c, 0xd0, 0x08, 0xb3, 0xa0, 0xc6, 0x2a, 0xda, 0xb7,
];

/// `domainName()` — `keccak256("AA v3 EVM Manager")`.
pub const DOMAIN_NAME: [u8; 32] = [
    0xb2, 0xa1, 0x61, 0xc1, 0xe1, 0xfe, 0x09, 0xf6, 0x31, 0x58, 0x5b, 0x3b, 0xda, 0x0e, 0x4a, 0x22,
    0xf3, 0x17, 0xd7, 0xc6, 0x63, 0xc5, 0x82, 0xa0, 0x7c, 0x1d, 0x68, 0x3e, 0x61, 0xfd, 0xcd, 0xb1,
];

/// `domainVersion()` — `keccak256("1")`.
pub const DOMAIN_VERSION: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c, 0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd, 0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

/// `registerType()` — selector 1.
pub const REGISTER_TYPE: [u8; 32] = [
    0xe6, 0xac, 0xe6, 0xc7, 0x0a, 0x9d, 0x92, 0xef, 0x85, 0x1c, 0x2e, 0x2a, 0x67, 0xb2, 0x30, 0x90,
    0x17, 0xb0, 0x51, 0xd3, 0x9e, 0x05, 0x54, 0xc7, 0x46, 0x27, 0x4a, 0x17, 0x69, 0x59, 0xac, 0x4f,
];

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        sha3::Digest::update(&mut h, p);
    }
    sha3::Digest::finalize(h).into()
}

/// A big-endian 32-byte word holding `v`.
pub fn num_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A big-endian 32-byte word holding a 20-byte address, left-padded.
pub fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// `evmDomainSeparatorFor(manager, domain)`.
pub fn domain_separator(manager: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    let alias_digest = keccak(&[manager]);
    let mut alias = [0u8; 20];
    alias.copy_from_slice(&alias_digest[12..32]);
    keccak(&[
        &DOMAIN_TYPE,
        &DOMAIN_NAME,
        &DOMAIN_VERSION,
        &addr_word(&alias),
        domain,
    ])
}

/// `eip712Digest(domainSeparator, structHash)` — `keccak(0x19 ‖ 0x01 ‖ sep ‖ structHash)`.
pub fn eip712_digest(sep: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19u8, 0x01u8][..], sep, struct_hash])
}

/// `evmAccountIdFor(manager, owner, salt)`.
pub fn evm_account_id(manager: &[u8; 32], owner: &[u8; 20], salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[&ACCOUNT_TAG, manager, &addr_word(owner), salt])
}

// ---- secp256k1 ----------------------------------------------------------------------------------

pub fn scalar(v: u64) -> IrValue {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bytes).expect("a valid scalar")
}

/// The FAB-native limbs of an IR value, as the circuit's input schema takes them.
pub fn natives(v: &IrValue) -> Vec<Fr> {
    encode_offcircuit(v)
        .into_iter()
        .map(|x| match x {
            IrValue::Native(f) => f,
            other => panic!("encode produced a non-native {other:?}"),
        })
        .collect()
}

/// Sign `digest` (a big-endian integer, RFC 6979) with secret `d` and nonce `k`, via upstream's own
/// off-circuit helpers.
pub fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> (IrValue, IrValue, IrValue) {
    let generator = IrValue::Secp256k1Point(k256::K256::generator());
    let mut le = *digest;
    le.reverse();
    let z = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).expect("z");

    let r_point = ec_mul_offcircuit(&generator, k).expect("kG");
    let (x, _y) = into_coordinates_offcircuit(&r_point).expect("coordinates");
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).expect("x bytes") else {
        panic!("into_bytes32 yields Bytes32");
    };
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &x_le).expect("r");

    let rd = mul_offcircuit(&r, d).expect("r·d");
    let z_rd = add_offcircuit(&z, &rd).expect("z + r·d");
    let k_inv = inv_offcircuit(k).expect("k⁻¹");
    let s = mul_offcircuit(&k_inv, &z_rd).expect("s");

    let pk = ec_mul_offcircuit(&generator, d).expect("dG");
    (r, s, pk)
}

/// `secp256k1EthereumAddress(pk)` off-circuit: keccak of the point's big-endian coordinates,
/// bytes 12..31.
pub fn ethereum_address(pk: &IrValue) -> [u8; 20] {
    let (x, y) = into_coordinates_offcircuit(pk).expect("coordinates");
    let be = |v: &IrValue| -> [u8; 32] {
        let IrValue::Bytes32(le) = into_bytes32_offcircuit(v).expect("bytes") else {
            panic!("into_bytes32 yields Bytes32");
        };
        let mut b = le;
        b.reverse();
        b
    };
    let digest = keccak(&[&be(&x), &be(&y)]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..32]);
    out
}

// ---- the payload --------------------------------------------------------------------------------

/// `struct ExecutePayload` off-circuit. Field order is the FAB slot order, so [`Payload::slots`] is
/// the circuit's first 24 inputs.
#[derive(Clone, Debug, Default)]
pub struct Payload {
    pub selector: u8,
    pub auth_mode: u8,
    pub account: [u8; 32],
    pub owner: [u8; 20],
    pub account_salt: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub primary_color: [u8; 32],
    pub primary_amount: u128,
    pub recipient_kind: u8,
    pub recipient: [u8; 32],
    pub to_account: [u8; 32],
    pub want_nonce: [u8; 32],
    pub want_color: [u8; 32],
    pub want_amount: u128,
    pub credit_account: [u8; 32],
}

fn u128_fr(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit")
}

impl Payload {
    /// The 24 argument slots, in declaration order.
    pub fn slots(&self) -> Vec<Fr> {
        let mut out = Vec::with_capacity(24);
        let mut b32 = |v: &[u8; 32], out: &mut Vec<Fr>| {
            let (hi, lo) = b32_slots(v);
            out.push(hi);
            out.push(lo);
        };
        out.push(Fr::from(u64::from(self.selector)));
        out.push(Fr::from(u64::from(self.auth_mode)));
        b32(&self.account, &mut out);
        out.push(Fr::from_le_bytes(&self.owner).expect("20 bytes fit"));
        b32(&self.account_salt, &mut out);
        out.push(Fr::from(self.nonce));
        out.push(Fr::from(self.valid_until));
        b32(&self.primary_color, &mut out);
        out.push(u128_fr(self.primary_amount));
        out.push(Fr::from(u64::from(self.recipient_kind)));
        b32(&self.recipient, &mut out);
        b32(&self.to_account, &mut out);
        b32(&self.want_nonce, &mut out);
        b32(&self.want_color, &mut out);
        out.push(u128_fr(self.want_amount));
        b32(&self.credit_account, &mut out);
        debug_assert_eq!(out.len(), 24);
        out
    }

    /// The EIP-712 struct-hash preimage for this payload's selector (selector 1 only here — the
    /// other benchmark scenarios are native-authorized and never build one).
    pub fn struct_hash(&self, manager: &[u8; 32]) -> [u8; 32] {
        let owner_word = addr_word(&self.owner);
        match self.selector {
            1 => keccak(&[
                &REGISTER_TYPE,
                manager,
                &self.account,
                &owner_word,
                &self.account_salt,
                &num_word(u128::from(self.valid_until)),
            ]),
            other => panic!("selector {other} has no EIP-712 struct hash in this harness"),
        }
    }
}

// ---- the ledger's answers -----------------------------------------------------------------------

/// The values the ledger hands back, in the order the circuit's `public_input` gates consume them.
///
/// A guarded-off gate consumes NOTHING, so this list holds exactly the reads the scenario's own
/// selector path takes — which is what makes the model small.
#[derive(Default, Debug, Clone)]
pub struct Reads(pub Vec<Fr>);

impl Reads {
    pub fn new() -> Self {
        Reads(Vec::new())
    }

    /// `kernel.self()` / any `Bytes<32>` read — two limbs.
    pub fn b32(&mut self, v: &[u8; 32]) -> &mut Self {
        let (hi, lo) = b32_slots(v);
        self.0.push(hi);
        self.0.push(lo);
        self
    }

    /// A `member` answer, or any `Boolean` popeq.
    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.0.push(Fr::from(u64::from(b)));
        self
    }

    /// A `Uint<8>` cell (`accountModes`).
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(Fr::from(u64::from(v)));
        self
    }

    /// A `Uint<128>` cell (`shieldedBalances` / `unshieldedBalances`).
    pub fn u128(&mut self, v: u128) -> &mut Self {
        self.0.push(u128_fr(v));
        self
    }

    /// A `Uint<64>` cell (`evmNonces`) / a coin's merkle-tree index.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.push(Fr::from(v));
        self
    }

    /// A `Bytes<20>` cell (`evmOwners`).
    pub fn bytes20(&mut self, v: &[u8; 20]) -> &mut Self {
        self.0.push(Fr::from_le_bytes(v).expect("20 bytes fit"));
        self
    }

    /// A `QualifiedShieldedCoinInfo` (`pools.lookup`) — six limbs.
    pub fn coin(
        &mut self,
        nonce: &[u8; 32],
        color: &[u8; 32],
        value: u128,
        mt_index: u64,
    ) -> &mut Self {
        self.b32(nonce);
        self.b32(color);
        self.u128(value);
        self.u64(mt_index);
        self
    }
}

/// One `execute` call, ready for [`crate::synth::synthesize`].
pub struct Scenario {
    pub name: &'static str,
    pub what: &'static str,
    pub payload: Payload,
    /// The `localOwnerSecret()` witness.
    pub owner_secret: [u8; 32],
    pub sig_r: IrValue,
    pub sig_s: IrValue,
    pub pk: IrValue,
    pub reads: Reads,
}

impl Scenario {
    /// The preimage skeleton: everything but `public_transcript_inputs`, which the synthesizer
    /// derives from the artifact.
    pub fn preimage(&self) -> ProofPreimage {
        let mut inputs = self.payload.slots();
        inputs.extend(natives(&self.sig_r));
        inputs.extend(natives(&self.sig_s));
        inputs.extend(natives(&self.pk));
        assert_eq!(
            inputs.len(),
            33,
            "24 payload slots + two 2-limb secp scalars + a 5-limb point"
        );

        let (sk_hi, sk_lo) = b32_slots(&self.owner_secret);

        // `execute` returns `[]`, so the communications commitment covers the raw inputs alone.
        let rand = Fr::from(0xb0_u64);
        let comm = transient_commit(&inputs[..], rand);

        ProofPreimage {
            inputs,
            private_transcript: vec![sk_hi, sk_lo],
            public_transcript_inputs: vec![],
            public_transcript_outputs: self.reads.0.clone(),
            binding_input: 0.into(),
            key_location: KeyLocation(Cow::Borrowed("execute")),
            communications_commitment: Some((comm, rand)),
        }
    }
}

// ---- fixtures (00012's exact bytes) -------------------------------------------------------------

pub fn self_addr() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..12].copy_from_slice(b"aa00012-self");
    a[31] = 0x11;
    a
}

pub fn deployment_domain() -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..14].copy_from_slice(b"aa00012-domain");
    d[31] = 0x22;
    d
}

pub fn owner_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..10].copy_from_slice(b"owner-secr");
    s[31] = 0x33;
    s
}

pub fn a_colour() -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..6].copy_from_slice(b"colour");
    c[31] = 0x44;
    c
}

pub fn a_recipient() -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..9].copy_from_slice(b"recipient");
    r[31] = 0x55;
    r
}

pub fn another_account() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..7].copy_from_slice(b"other-a");
    a[31] = 0x66;
    a
}

pub fn want_colour() -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..4].copy_from_slice(b"want");
    c[31] = 0x77;
    c
}

pub fn want_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..5].copy_from_slice(b"nonce");
    n[31] = 0x88;
    n
}

/// A signature that is well-formed but not over anything in particular — enough for the paths where
/// the ECDSA result is never asserted on (`authMode == 0`), where the contract still runs the
/// verification straight-line because the pinned backend cannot lower a guarded secp operation.
fn dummy_signature() -> (IrValue, IrValue, IrValue) {
    sign(&[7u8; 32], &scalar(0x5eed), &scalar(0xf00d))
}

/// The signing key and the ECDSA nonce. Any nonzero pair works.
fn signing_key() -> (IrValue, IrValue) {
    (scalar(0xA11CE), scalar(0xB0B))
}

/// The EOA the signature authorises: `secp256k1EthereumAddress(d·G)`.
fn signer_address() -> [u8; 20] {
    let (d, k) = signing_key();
    let (_r, _s, pk) = sign(&[0u8; 32], &d, &k);
    ethereum_address(&pk)
}

/// The six reads of the native arm of `authenticatedActionAccount`, in source order.
fn native_auth_reads(reads: &mut Reads) {
    reads.bool(true); //   `accounts.member(nativeAccount)`
    reads.bool(true); //   `accountModes.member(nativeAccount)`
    reads.u8(0); //        `accountModes.lookup(acct)` — native mode
    reads.u8(0); //        `accountModes.lookup(acct)` — re-read at the second assert
    reads.bool(false); //  `evmOwners.member(acct)`
    reads.bool(false); //  `evmNonces.member(acct)`
}

/// The two `assertLiveDeadline` reads: `blockTimeGte(validUntil - 3600)` then
/// `blockTimeLt(validUntil)` — `false` then `true`.
fn live_deadline_reads(reads: &mut Reads) {
    reads.bool(false);
    reads.bool(true);
}

// ---- the four benchmark scenarios ---------------------------------------------------------------

/// Selector 0 — native registration. `custodyDispatch` is never entered.
pub fn sel0_native_registration() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let mut reads = Reads::new();
    reads.b32(&self_addr()); // `kernel.self()`
    // `deploymentDomain` is GUARDED OFF for selector 0.
    reads.bool(false); // `accounts.member(account)`
    reads.bool(false); // `accountModes.member(account)`
    Scenario {
        name: "sel0-native-registration",
        what: "selector 0 — native registration (custodyDispatch skipped entirely)",
        payload: Payload {
            selector: 0,
            auth_mode: 0,
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 1 — EVM registration. The only selector that REQUIRES `authMode == 1`, so it is the
/// only benchmark scenario that carries a real EIP-712 signature and runs the deadline checks.
pub fn sel1_evm_registration() -> Scenario {
    let manager = self_addr();
    let owner = signer_address();
    let mut salt = [0u8; 32];
    salt[..4].copy_from_slice(b"salt");
    salt[31] = 0x99;

    let payload = Payload {
        selector: 1,
        auth_mode: 1,
        account: evm_account_id(&manager, &owner, &salt),
        owner,
        account_salt: salt,
        nonce: 0,
        valid_until: 4_000,
        ..Payload::default()
    };
    let sep = domain_separator(&manager, &deployment_domain());
    let digest = eip712_digest(&sep, &payload.struct_hash(&manager));
    let (d, k) = signing_key();
    let (r, s, pk) = sign(&digest, &d, &k);

    let mut reads = Reads::new();
    reads.b32(&manager); //             `kernel.self()`
    reads.b32(&deployment_domain()); // `deploymentDomain`
    live_deadline_reads(&mut reads);
    reads.bool(false); // `accounts.member(account)`
    reads.bool(false); // `accountModes.member(account)`
    Scenario {
        name: "sel1-evm-registration",
        what: "selector 1 — EVM registration (authMode 1: real EIP-712 signature, live deadline)",
        payload,
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 2 — withdraw shielded, native authorization. The `sendShielded` leg.
pub fn sel2_withdraw_shielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(true); //  `pools.member(col)`
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0); // `pools.lookup(col)`
    reads.b32(&self_addr()); // `sendShielded`'s `kernel.self()`
    reads.b32(&self_addr()); // `repoolOrRemove`'s `insertCoin(… right(kernel.self()))`
    Scenario {
        name: "sel2-withdraw-shielded-native",
        what: "selector 2 — withdraw shielded, native (needsPool holds; sendShielded + repool)",
        payload: Payload {
            selector: 2,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            // PR#10 (project 00016): a withdrawal may only pay a User (kind 0).
            recipient_kind: 0,
            recipient: a_recipient(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 3 — withdraw UNSHIELDED, native authorization. Provable only as of PR#9.
pub fn sel3_withdraw_unshielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //   `unshieldedBalances.member(debitKey)` — the muxed family is unshielded
    reads.u128(1_000); //  `unshieldedBalances.lookup(debitKey)`
    reads.bool(false); //  `unshieldedBalance(col) < val` — the contract holds enough
    Scenario {
        name: "sel3-withdraw-unshielded-native",
        what: "selector 3 — withdraw unshielded, native (User-tagged payout; PR#9 made it provable)",
        payload: Payload {
            selector: 3,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            recipient_kind: 0,
            recipient: a_recipient(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 4 — internal SHIELDED transfer, native authorization. Provable only as of PR#9.
pub fn sel4_transfer_shielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `accounts.member(p.toAccount)` — reached because `isTransfer` held
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(false); // `shieldedBalances.member(creditKey)` — a fresh credit cell
    Scenario {
        name: "sel4-transfer-shielded-native",
        what: "selector 4 — internal shielded transfer, native (PR#9 made it provable)",
        payload: Payload {
            selector: 4,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            to_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 5 — internal UNSHIELDED transfer, native authorization. Provable only as of PR#9.
pub fn sel5_transfer_unshielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `accounts.member(p.toAccount)`
    reads.bool(true); //  `unshieldedBalances.member(debitKey)`
    reads.u128(1_000); // `unshieldedBalances.lookup(debitKey)`
    reads.bool(false); // `unshieldedBalances.member(creditKey)`
    Scenario {
        name: "sel5-transfer-unshielded-native",
        what: "selector 5 — internal unshielded transfer, native (PR#9 made it provable)",
        payload: Payload {
            selector: 5,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            to_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 6 — open swap, native authorization: the FR-308 open-offer leg, the want leg and the
/// credit write — the widest single path through `custodyDispatch`.
pub fn sel6_open_swap_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(true); //  `pools.member(col)`
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0); // `pools.lookup(col)`
    reads.bool(true); //  `accounts.member(p.creditAccount)`
    reads.b32(&self_addr()); // the open leg's `kernel.self()`
    reads.b32(&self_addr()); // the change coin's `insertCoin(… right(kernel.self()))`
    reads.b32(&self_addr()); // `receiveShielded`'s `kernel.self()`
    reads.bool(false); //    `pools.member(p.wantColor)` — a colour the pool does not hold yet
    reads.b32(&self_addr()); // the fresh-colour `insertCoin(… right(kernel.self()))`
    reads.bool(false); //    `shieldedBalances.member(creditKey)`
    Scenario {
        name: "sel6-open-swap-native",
        what: "selector 6 — open swap, native, fresh want colour (widest custodyDispatch path)",
        payload: Payload {
            selector: 6,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            recipient_kind: 0,
            want_nonce: want_nonce(),
            want_color: want_colour(),
            want_amount: 250,
            credit_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// The scenario set, in selector order — **one per selector, all seven**.
///
/// 00018 could only carry four (0, 1, 2, 6): F-00012-08 meant selectors 3, 4 and 5 had no accepted
/// run on the pre-PR#9 statement, so there was nothing to prove. PR#9's `safeGive` clamp fixed
/// that, and this project's Phase-3 gate confirms all three accept.
pub fn all_scenarios() -> Vec<Scenario> {
    vec![
        sel0_native_registration(),
        sel1_evm_registration(),
        sel2_withdraw_shielded_native(),
        sel3_withdraw_unshielded_native(),
        sel4_transfer_shielded_native(),
        sel5_transfer_unshielded_native(),
        sel6_open_swap_native(),
    ]
}

pub fn scenario_by_name(name: &str) -> Scenario {
    match name {
        "sel0-native-registration" => sel0_native_registration(),
        "sel1-evm-registration" => sel1_evm_registration(),
        "sel2-withdraw-shielded-native" => sel2_withdraw_shielded_native(),
        "sel3-withdraw-unshielded-native" => sel3_withdraw_unshielded_native(),
        "sel4-transfer-shielded-native" => sel4_transfer_shielded_native(),
        "sel5-transfer-unshielded-native" => sel5_transfer_unshielded_native(),
        "sel6-open-swap-native" => sel6_open_swap_native(),
        other => panic!("unknown scenario: {other}"),
    }
}
