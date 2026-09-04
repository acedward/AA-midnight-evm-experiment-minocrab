//! The off-circuit model of one `execute` call: its arguments, its witness, and the ledger's
//! answers.
//!
//! This is the hand-written half of a scenario (the transcript itself is derived — see
//! [`super::synth`]). It is deliberately small, and the reason is a property of the v3 simulator
//! worth stating: **a guarded-off `Impact` consumes no transcript and a guarded-off `PublicInput`
//! consumes no output** (`crates/minocrab-sim/src/v3.rs:457-480, 625-655`). `execute` mints 64
//! read gates across seven mutually exclusive selector paths, so any ONE run reads a dozen-odd
//! values. [`Reads`] is the list of those values, in the order the circuit consumes them.
//!
//! ## `ownerCommitment`, computed off-circuit — and why that is the test of the flagged risk
//!
//! The Phase-3.3 hand-over flagged `ownerCommitment` as the highest-blast-radius helper in the port
//! and the one with no frozen fixture: it was transcribed from minocrab-std's **v2-only**
//! `persistentCommit`, whose preimage is rand-then-value (`sk ‖ tag21` under `[bytes 32,
//! bytes 21]`). [`owner_commitment`] below is a THIRD, independent statement of that recipe, in
//! plain Rust over FAB + SHA-256.
//!
//! It is load-bearing, not decorative. Every action selector supplies `p.account` as an ARGUMENT,
//! and `authenticatedActionAccount` asserts `acct == p.account` where `acct` is the circuit's own
//! `ownerCommitment(localOwnerSecret())`. So a scenario built with this function is accepted by the
//! **compactc artifact** only if this recipe agrees with compactc's `persistentCommit` byte for
//! byte. That check happens before the port is ever run, which is what makes it independent: it
//! confirms the recipe against the reference, and the differential then confirms the port against
//! the same recipe.

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
use minocrab_zkir::v3::{IrType, IrValue};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::borrow::Cow;

// ---- FAB helpers (the same shapes minocrab's own reference model uses) --------------------------

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
/// `persistentHash`.
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

// ---- the contract's own hashes, off-circuit ----------------------------------------------------

/// `ownerCommitment(sk)` = `persistentCommit<Bytes<21>>("aa:manager:owner:v1.0", sk)` —
/// SHA-256 over `sk ‖ "aa:manager:owner:v1.0"` under `[bytes 32, bytes 21]` (rand THEN value).
pub fn owner_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (hi, lo) = b32_slots(sk);
    let tag = Fr::from_le_bytes(b"aa:manager:owner:v1.0").expect("21 bytes fit");
    fab_sha256(vec![atom(32), atom(21)], &[hi, lo, tag])
}

/// `shieldedKey(acct, colour)` / `unshieldedKey(acct, colour)` — `persistentHash` over the three
/// 32-byte words `[acct, colour, familyTag]`.
pub fn family_key(acct: &[u8; 32], colour: &[u8; 32], tag: &[u8; 32]) -> [u8; 32] {
    let (a_hi, a_lo) = b32_slots(acct);
    let (c_hi, c_lo) = b32_slots(colour);
    let (t_hi, t_lo) = b32_slots(tag);
    fab_sha256(
        vec![atom(32), atom(32), atom(32)],
        &[a_hi, a_lo, c_hi, c_lo, t_hi, t_lo],
    )
}

pub fn shielded_tag() -> [u8; 32] {
    pad32("aa:manager:shielded:v1")
}

pub fn unshielded_tag() -> [u8; 32] {
    pad32("aa:manager:unshielded:v1")
}

// ---- the frozen EIP-712 constants, off-circuit --------------------------------------------------
//
// Byte-identical to `manager_port::eip712`'s, and used only to build a signature a scenario can be
// ACCEPTED with. They are not the fixture check — `tests/eip712_fixtures.rs` is (60 cases, 180
// frozen-byte comparisons against `harness/src/auth/fixtures/v1.json`).

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
/// off-circuit helpers — the same construction minocrab's reference model uses
/// (`crates/minocrab-contracts/tests/vault/prims.rs:217`).
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

// ---- the payload ---------------------------------------------------------------------------------

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

    /// The EIP-712 struct-hash preimage for this payload's selector, as the 32-byte words
    /// `evmStructHashFor` concatenates (`contracts/modules/Eip712.compact:158-192`).
    pub fn struct_hash(&self, manager: &[u8; 32]) -> [u8; 32] {
        use manager_port::eip712 as e;
        let owner_word = addr_word(&self.owner);
        match self.selector {
            1 => keccak(&[
                &e::REGISTER_TYPE,
                manager,
                &self.account,
                &owner_word,
                &self.account_salt,
                &num_word(u128::from(self.valid_until)),
            ]),
            2 | 3 => {
                let t = if self.selector == 2 {
                    e::WITHDRAW_SHIELDED_TYPE
                } else {
                    e::WITHDRAW_UNSHIELDED_TYPE
                };
                keccak(&[
                    &t,
                    manager,
                    &self.account,
                    &owner_word,
                    &num_word(u128::from(self.nonce)),
                    &num_word(u128::from(self.valid_until)),
                    &self.primary_color,
                    &num_word(self.primary_amount),
                    &num_word(u128::from(self.recipient_kind)),
                    &self.recipient,
                ])
            }
            4 | 5 => {
                let t = if self.selector == 4 {
                    e::TRANSFER_SHIELDED_TYPE
                } else {
                    e::TRANSFER_UNSHIELDED_TYPE
                };
                keccak(&[
                    &t,
                    manager,
                    &self.account,
                    &owner_word,
                    &num_word(u128::from(self.nonce)),
                    &num_word(u128::from(self.valid_until)),
                    &self.to_account,
                    &self.primary_color,
                    &num_word(self.primary_amount),
                ])
            }
            6 => keccak(&[
                &e::OPEN_SWAP_TYPE,
                manager,
                &self.account,
                &owner_word,
                &num_word(u128::from(self.nonce)),
                &num_word(u128::from(self.valid_until)),
                &self.primary_color,
                &num_word(self.primary_amount),
                &num_word(u128::from(self.recipient_kind)),
                &self.recipient,
                &self.want_nonce,
                &self.want_color,
                &num_word(self.want_amount),
                &self.credit_account,
            ]),
            other => panic!("selector {other} has no EIP-712 struct hash"),
        }
    }
}

/// `evmDomainSeparatorFor(manager, domain)` (`contracts/modules/Eip712.compact:148-154`).
pub fn domain_separator(manager: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    use manager_port::eip712 as e;
    let alias_digest = keccak(&[manager]);
    let mut alias = [0u8; 20];
    alias.copy_from_slice(&alias_digest[12..32]);
    keccak(&[
        &e::DOMAIN_TYPE,
        &e::DOMAIN_NAME,
        &e::DOMAIN_VERSION,
        &addr_word(&alias),
        domain,
    ])
}

/// `eip712Digest(domainSeparator, structHash)` — `keccak(0x19 ‖ 0x01 ‖ sep ‖ structHash)`.
pub fn eip712_digest(sep: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19u8, 0x01u8][..], sep, struct_hash])
}

/// `evmAccountIdFor(manager, owner, salt)` (`contracts/modules/Eip712.compact:139-144`).
pub fn evm_account_id(manager: &[u8; 32], owner: &[u8; 20], salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[
        &manager_port::eip712::ACCOUNT_TAG,
        manager,
        &addr_word(owner),
        salt,
    ])
}

// ---- the ledger's answers ------------------------------------------------------------------------

/// The values the ledger hands back, in the order the circuit's `public_input` gates consume them.
///
/// A guarded-off gate consumes NOTHING, so this list holds exactly the reads the scenario's own
/// selector path takes — which is what makes the model small. Each `push` is named after the
/// contract's read so the list can be checked against the source line by line.
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

    /// A `Uint<64>` cell (`evmNonces`).
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.push(Fr::from(v));
        self
    }

    /// A `Uint<128>` cell (`shieldedBalances` / `unshieldedBalances`).
    pub fn u128(&mut self, v: u128) -> &mut Self {
        self.0.push(u128_fr(v));
        self
    }

    /// A `Bytes<20>` cell (`evmOwners`).
    pub fn bytes20(&mut self, v: &[u8; 20]) -> &mut Self {
        self.0.push(Fr::from_le_bytes(v).expect("20 bytes fit"));
        self
    }

    /// A `QualifiedShieldedCoinInfo` (`pools.lookup`) — six limbs.
    pub fn coin(&mut self, nonce: &[u8; 32], color: &[u8; 32], value: u128, mt_index: u64) -> &mut Self {
        self.b32(nonce);
        self.b32(color);
        self.u128(value);
        self.u64(mt_index);
        self
    }
}

/// One `execute` call, ready for [`super::synth::synthesize`].
pub struct Scenario {
    pub name: &'static str,
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
    /// derives from the compactc artifact.
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
            communications_commitment: Some((comm, rand)),
            key_location: KeyLocation(Cow::Borrowed("manager-port-00012-execute")),
        }
    }
}
