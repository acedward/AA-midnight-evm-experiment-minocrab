//! Phase 3.6 — `export circuit execute(payload, sig, pk): []` (`contracts/manager.compact:340-398`),
//! the contract's only externally callable registration/debit gateway and 86.7% of its provable
//! rows.
//!
//! **Compact twin**: `contracts/manager.compact` — THE PRESET, the deployable contract that
//! composes the nine modules and owns the ledger field `deploymentDomain`, the constructor,
//! `assertLiveDeadline` and `execute` itself.
//!
//! **Circuits ported here** (1 of the nine key-emitting circuits, and 86.7% of the provable rows):
//! [`execute`]. The preset's other public wrappers — `depositShielded`, `depositUnshielded` and the
//! six readers — are ported in the module that owns their state, because that is where their bodies
//! are; [`crate::circuits`] is the list that says which file each of the nine lives in. The
//! constructor is not ported: it emits no key.
//!
//! ## Why this circuit is hand-written instead of `#[circuit]`
//!
//! The compactc schema is 24 `Scalar<BLS12-381>` payload slots, then **two `Scalar<Secp256k1>`**
//! (the signature's `r`/`s`), then one `Point<Secp256k1>` (the public key). minocrab has a
//! `CircuitArg` impl for `Secp256k1Point` but none for a bare `Secp256k1Scalar`, and the
//! `#[circuit]` macro can only declare arguments through that trait — so the signature could not be
//! spelled. Adding a local wrapper type with a hand-written `CircuitAbi`/`CircuitArg` pair would
//! have to claim a `Prim` for a scalar slot, and none of the variants means that; `Prim::Point`
//! only *happens* to have the right effect (no constraint). Rather than encode that coincidence in
//! a type, the entry point is written the way `entry_out` writes it — declare, constrain, body,
//! finish — which is a handful of lines and states the schema outright. This is recorded as a
//! **minocrab expressiveness gap** (see the plan's Phase-3 findings); it costs no rows and changes
//! no statement, only the spelling.
//!
//! The two-phase discipline `entry_out` enforces is kept literally: every `Circuit3::arg` call
//! precedes every instruction (ZKIR requires it), and the input constraints come from the ARGUMENT
//! TYPES, not from hand-written `assert_bits`. The result is compactc's own opening: 24
//! `constrain_bits` in slot order, and none for the signature or the key — which is exactly what
//! `execute.zkir` instructions 0-23 are, and exactly which slots it leaves unconstrained.
//!
//! ## The shape, against the artifact
//!
//! Every ledger operation below is in the position the compactc op stream puts it
//! (`evidence/00012/raw/00012-p3.4-execute-impact-ops.txt`):
//!
//! | ops | what |
//! |---|---|
//! | 1-3 | `kernel.self()` — `manager` |
//! | 4-6 | `deploymentDomain`, guarded by `selector != 0` (the ternary's else arm) |
//! | 7-66 | `authenticatedActionAccount`, native arm then EVM arm |
//! | 67-76 | `assertLiveDeadline`, guarded by `isEvmAuthorized` |
//! | 77-101 | `registerAccount` + `evmOwners.insert` |
//! | 102-399 | `custodyDispatch`, guarded by `!isRegistration` |
//! | 400-404 | `evmNonces.insert`, guarded by `isEvmAuthorized` |

use minocrab::v3::{Circuit3, Compiled3, Secp256k1PointT, Secp256k1ScalarT};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    is_true, kernel, not, secp256k1_ecdsa_verify, secp256k1_ethereum_address, ArgPath, Bool, Bytes,
    CircuitArg, Secp256k1EcdsaSignature, Uint, B32,
};

use crate::account_registry::{gateway_account, owner_commitment, register_account};
use crate::action_envelope::{assert_action_envelope, ExecutePayload, Selectors};
use crate::checks::b32_eq;
use crate::custody::custody_dispatch;
use crate::eip712::{evm_account_id_for, evm_digest_for};
use crate::ledger::MANAGER;

/// `export circuit execute(payload: ExecutePayload, sig: Secp256k1EcdsaSignature, pk: Secp256k1Point): []`
pub fn execute() -> Compiled3 {
    let mut c = Circuit3::new();

    // ---- phase 1: DECLARATION ONLY (no instruction may precede an input) ------------------------
    let payload = ExecutePayload::<Private>::declare(&mut c, &ArgPath::root("payload"));
    let sig = Secp256k1EcdsaSignature::<Private> {
        r: c.arg::<Secp256k1ScalarT>("sig_r"),
        s: c.arg::<Secp256k1ScalarT>("sig_s"),
    };
    let pk = c.arg::<Secp256k1PointT>("pk");

    // ---- phase 2: compactc's input constraints, derived from the types --------------------------
    payload.constrain(&mut c);

    // ---- the body -------------------------------------------------------------------------------
    body(&mut c, payload, sig, pk);

    // `true`: every exported entry point commits to its cross-contract communications, which is
    // what `do_communications_commitment` is in the artifact (`execute.zkir` says `true`).
    c.finish(true)
}

fn body(
    c: &mut Circuit3,
    payload: ExecutePayload<Private>,
    sig: Secp256k1EcdsaSignature<Private>,
    pk: minocrab::v3::Wire3<Secp256k1PointT, Private>,
) {
    // `const p = disclose(payload);`
    let p = disclose_payload(c, payload);
    let s = Selectors::of(c, &p);

    // `assertActionEnvelope(p);`
    assert_action_envelope(c, &p, &s);

    // `const manager = kernel.self().bytes;`
    let manager = kernel::self_address(c).bytes();

    // `const digest = p.selector == 0 ? default<Bytes<32>> : evmDigestFor(manager, deploymentDomain, p);`
    //
    // The `deploymentDomain` READ is an argument of the else arm, so compactc guards it by
    // `selector != 0` — op 4-6. Writing it inside the `otherwise` closure reproduces that exactly.
    let zero = c.constant(0u64);
    let zero_b32 = B32 { hi: zero, lo: zero };
    let digest = c.when_value(s.s0, |_c| zero_b32).otherwise(|c| {
        let domain = MANAGER.deployment_domain.read(c);
        evm_digest_for(c, &manager, &domain, &p)
    });

    // `const signatureOk = disclose(secp256k1EcdsaVerify(digest, sig, pk));`
    // `const signer = disclose(secp256k1EthereumAddress(pk));`
    //
    // The ECDSA operations stay STRAIGHT-LINE, which the contract's own comment says is forced:
    // "the pinned ZKIR-v3 backend cannot lower guarded secp operations" (`contracts/manager.compact:336`).
    let signature_ok = c.region("ecdsa: verify", |c| {
        let ok = secp256k1_ecdsa_verify(c, &digest.private(), &sig, pk);
        c.disclose(ok, "signatureOk")
    });
    let signer: Bytes<20, Public> = c.region("ecdsa: signer address", |c| {
        let addr = secp256k1_ethereum_address(c, pk);
        Bytes::from_field_unchecked(c.disclose(addr, "signer"))
    });

    let is_evm_registration = s.s1;
    let is_registration = c.cond_select(s.s0, 1u64, s.s1);
    let is_evm_authorized = p.auth_mode.eq(1u64).into_wire(c);
    let not_evm_registration = c.not(is_evm_registration);
    let is_evm_action = c.cond_select(is_evm_authorized, not_evm_registration, 0u64);

    // `const nativeAccount = ownerCommitment(localOwnerSecret());`
    let native_account = {
        let sk = B32::<Private> {
            hi: c.witness(),
            lo: c.witness(),
        };
        sk.constrain_input(c);
        // `disclose(sk)` inside `ownerCommitment` — the secret's limbs enter a public hash.
        let sk = B32::<Public> {
            hi: c.disclose(sk.hi, "localOwnerSecret"),
            lo: c.disclose(sk.lo, "localOwnerSecret"),
        };
        owner_commitment(c, &sk)
    };

    // `const evmRegistrationAccount = evmAccountIdFor(manager, p.owner, p.accountSalt);`
    let evm_registration_account =
        evm_account_id_for(c, &manager, p.owner.field(), &p.account_salt);
    let ids_match = b32_eq(c, &evm_registration_account, &p.account);
    c.assert(
        not(is_true(Bool::from_field_unchecked(is_evm_registration)))
            .or(ids_match)
            .message("EVM registration account id mismatch"),
    );

    // `const account = gatewayAccount(p, nativeAccount, evmRegistrationAccount);`
    let account = gateway_account(c, &s, &p, &native_account, &evm_registration_account);

    // `if (isEvmAuthorized) { assertLiveDeadline(p.validUntil); }`
    c.when(is_evm_authorized, |c| {
        assert_live_deadline(c, p.valid_until);
    });

    let sig_ok = Bool::from_field_unchecked(signature_ok);
    let signer_matches = signer.eq(p.owner);
    c.assert(
        not(is_true(Bool::from_field_unchecked(is_evm_registration)))
            .or(is_true(sig_ok))
            .message("EVM registration signature does not verify"),
    );
    c.assert(
        not(is_true(Bool::from_field_unchecked(is_evm_registration)))
            .or(signer.eq(p.owner))
            .message("EVM registration signer does not match owner"),
    );
    c.assert(
        not(is_true(Bool::from_field_unchecked(is_evm_action)))
            .or(is_true(sig_ok))
            .message("EVM signature does not verify"),
    );
    let _ = signer_matches;
    c.assert(
        not(is_true(Bool::from_field_unchecked(is_evm_action)))
            .or(signer.eq(p.owner))
            .message("EVM signer does not control account"),
    );

    // `if (isRegistration) { registerAccount(account, (isEvmRegistration ? 1 : 0) as Uint<8>); }`
    // The mode IS the `isEvmRegistration` wire — compactc pushes it straight into the insert
    // (op 94: `push_s(cell<1>[%t.79])`).
    c.when(is_registration, |c| {
        let mode = Uint::<8, Public>::from_field_unchecked(is_evm_registration);
        register_account(c, &account, mode);
    });
    // `if (isEvmRegistration) { evmOwners.insert(account, p.owner); }`
    c.when(is_evm_registration, |c| {
        MANAGER.evm_owners.insert(c, &account, &p.owner);
    });

    // `if (!isRegistration) {
    //    custodyDispatch(p, account, isRegistered(p.toAccount), isRegistered(p.creditAccount)); }`
    //
    // THE REGISTRY-TO-CUSTODY SEAM (product `41de69d`, `contracts/manager.compact:378-380`). The
    // two membership facts custody needs are read HERE, because `Custody.compact` holds no registry
    // state, and passed down as arguments. They are evaluated in argument order — `toAccount`
    // first, `creditAccount` second — unconditionally under this block's `!isRegistration` guard,
    // where before the split each was read inside `custodyDispatch` behind the guard of the assert
    // that consumed it. See [`custody_dispatch`] for the whole story.
    let not_registration = c.not(is_registration);
    c.when(not_registration, |c| {
        let to_registered = MANAGER.accounts.member(c, &p.to_account);
        let credit_registered = MANAGER.accounts.member(c, &p.credit_account);
        custody_dispatch(c, &p, &s, &account, to_registered, credit_registered);
    });

    // The sole checked nonce write, deliberately after custody dispatch.
    let one = Uint::<64, Public>::constant(c, 1);
    let incremented = {
        let sum = c.add(p.nonce.field(), one.field());
        let w = Uint::<64, Public>::from_field_unchecked(sum);
        w.constrain_input(c);
        Uint::<64, Public>::from_field_unchecked(c.copy(sum))
    };
    c.assert(
        not(is_true(Bool::from_field_unchecked(is_evm_action)))
            .or(incremented.gt(p.nonce))
            .message("EVM nonce overflow"),
    );
    let stored_nonce = Uint::<64, Public>::from_field_unchecked(c.cond_select(
        is_evm_registration,
        0u64,
        incremented.field(),
    ));
    c.when(is_evm_authorized, |c| {
        MANAGER.evm_nonces.insert(c, &account, &stored_nonce);
    });
}

/// `disclose(payload)` — every slot of the struct, under one label.
///
/// Compact discloses the whole struct with a single `disclose(payload)`; a disclosure record is
/// metadata (no instruction, no row), so fanning the same label over the slots is the same
/// statement about what becomes public.
fn disclose_payload(c: &mut Circuit3, p: ExecutePayload<Private>) -> ExecutePayload<Public> {
    const L: &str = "payload";
    let b32 = |c: &mut Circuit3, v: B32<Private>| B32::<Public> {
        hi: c.disclose(v.hi, L),
        lo: c.disclose(v.lo, L),
    };
    ExecutePayload {
        selector: Uint::from_field_unchecked(c.disclose(p.selector.field(), L)),
        auth_mode: Uint::from_field_unchecked(c.disclose(p.auth_mode.field(), L)),
        account: b32(c, p.account),
        owner: Bytes::from_field_unchecked(c.disclose(p.owner.field(), L)),
        account_salt: b32(c, p.account_salt),
        nonce: Uint::from_field_unchecked(c.disclose(p.nonce.field(), L)),
        valid_until: Uint::from_field_unchecked(c.disclose(p.valid_until.field(), L)),
        primary_color: b32(c, p.primary_color),
        primary_amount: Uint::from_field_unchecked(c.disclose(p.primary_amount.field(), L)),
        recipient_kind: Uint::from_field_unchecked(c.disclose(p.recipient_kind.field(), L)),
        recipient: b32(c, p.recipient),
        to_account: b32(c, p.to_account),
        want_nonce: b32(c, p.want_nonce),
        want_color: b32(c, p.want_color),
        want_amount: Uint::from_field_unchecked(c.disclose(p.want_amount.field(), L)),
        credit_account: b32(c, p.credit_account),
    }
}

/// `assertLiveDeadline(validUntil)` (`contracts/manager.compact:310-327`). `execute` calls it inside
/// `if (isEvmAuthorized)`, so the caller opens that scope and this body inherits it.
///
/// Three asserts in source order: the horizon is representable, the deadline is not further out
/// than 3600 seconds, and it has not passed.
pub fn assert_live_deadline(c: &mut Circuit3, valid_until: Uint<64, minocrab::Public>) {
    c.assert(
        valid_until
            .gt(3600u64)
            .message("EVM authorization deadline cannot satisfy the horizon"),
    );

    // `(validUntil - 3600) as Uint<64>` — Compact inserts an underflow guard before every `-`,
    // and `sub_with` emits exactly that guard, in the same order, at the same width. The assert
    // above already establishes the precondition, so the emitted guard is the same redundant-but-
    // present check compactc emits.
    let horizon = Uint::<64, minocrab::Public>::constant(c, 3600);
    let earliest = valid_until.sub_with(c, horizon, "result of subtraction would be negative");

    let gte = minocrab_std::v3::kernel::block_time_gte(c, earliest);
    c.assert(is_true(gte).message("EVM authorization deadline exceeds 3600-second horizon"));

    let lt = minocrab_std::v3::kernel::block_time_lt(c, valid_until);
    c.assert(is_true(lt).message("EVM authorization has expired"));
}
