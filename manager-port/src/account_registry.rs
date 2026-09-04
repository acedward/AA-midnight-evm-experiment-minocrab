//! `contracts/modules/AccountRegistry.compact` — who is allowed to ask.
//!
//! **Compact twin**: `contracts/modules/AccountRegistry.compact`, which owns the ledger fields
//! `accounts`, `accountModes`, `evmOwners` and `evmNonces`, the witness `localOwnerSecret`, and
//! **every write to the registry**.
//!
//! **Circuits ported here** (2 of the nine key-emitting circuits): [`is_registered`] and
//! [`account_record`]. The module's other exports — `ownerCommitment`,
//! `authenticatedNativeAccount`, `registerAccount`, `authenticatedActionAccount`, `gatewayAccount`,
//! `_setEvmOwner`, `_setEvmNonce` — are helpers `execute` composes; `myAccount` emits no key and is
//! not ported. `_setEvmOwner` / `_setEvmNonce` are single ledger inserts written inline at their
//! two call sites in [`crate::execute`].
//!
//! **Guard ORDER and the refusal set are the product's behaviour** (FR-204), so this module keeps
//! both: every assert appears in the same relative order as the Compact source and carries the
//! same message text. Messages are metadata in minocrab (no instruction, no row), exactly as in
//! Compact, so preserving them is free and makes a failed proof diagnosable.
//!
//! ## Guarding convention
//!
//! These helpers do not take a `guard` parameter. Compact's `if` is
//! [`Circuit3::when`](minocrab::v3::Circuit3::when), which pushes an AMBIENT guard that every
//! enclosed ledger operation and every enclosed `assert` picks up, lowered as
//! `cond_select(outer, inner, 0)` — compactc's own `&&`. Passing an explicit guard *inside* such a
//! scope would conjoin it with the ambient one a second time and emit an extra instruction per
//! call, so the call sites open a scope and the helpers stay plain. That also makes Compact's
//! nesting and this port's nesting the same shape, which is what a reader checks.
//!
//! ## The registry-to-custody seam
//!
//! Custody holds no registry state, so the three membership facts it needs
//! (`isRegistered(account)` per deposit, `isRegistered(p.toAccount)` and
//! `isRegistered(p.creditAccount)` in `execute`) are read HERE — through `accounts.member` — and
//! passed into [`crate::custody`] as Booleans. See [`crate::custody::custody_dispatch`].
//!
//! ## What the readers have in common, and why that matters to the comparison
//!
//! Every read-only circuit in this contract is a disclosure, one or two ledger reads, and a return.
//! The Phase-2 construct survey measured the byte-chain opcodes (`div_mod_power_of_two` /
//! `reconstitute_field` / their `cond_select`s) at **0.0%** of these circuits' instructions — the
//! entire minocrab opportunity on this contract sits in `execute`. `isRegistered`'s Δ=0 was the
//! first confirmation; the other readers are the rest of the falsification surface.
//!
//! ## The one structural trap: Compact's early `return` is a GUARD
//!
//! [`account_record`] is a chain of `if (…) { return …; }` blocks. A circuit has no control flow, so
//! compactc compiles every block and each one's reads and asserts are emitted under its own
//! condition AND the negation of every earlier one — the same lowering
//! [`crate::action_envelope`] documents for `assertActionEnvelope`.
//! [`Circuit3::when_value`](minocrab::v3::Circuit3::when_value) is that lowering: it pushes an
//! ambient guard the enclosed ledger operations and asserts pick up, and selects the value at the
//! end.
//!
//! ## The short-circuit trap, again
//!
//! `!evmOwners.member(acct) && !evmNonces.member(acct)` does NOT read `evmNonces` unless the left
//! operand held: the compactc artifact guards that second `member` by `t.5 && !t.7`
//! (`accountRecord.zkir:38`). A minocrab `Check::and` is an inert descriptor and would not guard
//! the read — the read already happened at the call site — so each short-circuited read is written
//! as a scope. Same for `evmOwners.member(acct) && evmNonces.member(acct)` in the EVM arm.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    circuit, is_true, not, Bool, Bytes, CircuitOut, Disclose, Discloses, Select, Uint, Vis3, B32,
};

use crate::action_envelope::{ExecutePayload, Selectors};
use crate::checks::{b32_eq, b32_is_nonzero};
use crate::disclosures::{Account, Owner};
use crate::ledger::MANAGER;

/// `ownerCommitment(sk)` (`contracts/modules/AccountRegistry.compact:85-87`) —
/// `persistentCommit<Bytes<21>>("aa:manager:owner:v1.0", disclose(sk))`.
///
/// **`persistentCommit` has no v3 spelling in minocrab** (it is v2-only, `minocrab-std/src/hash.rs:43`),
/// so it is transcribed here from the v2 body, which is itself compactc's lowering: a
/// `persistentHash` whose preimage is **rand-then-value** with the alignment `bytes 32` consed onto
/// the value's atoms. Here `rand` is the 32-byte secret and `value` is the 21-byte domain string,
/// so the preimage is `sk ‖ "aa:manager:owner:v1.0"` under alignment `[bytes 32, bytes 21]`.
///
/// This is the highest-blast-radius helper in the port: it defines account identity, so every
/// native authorization path and every ledger key derives from it. It is not checked by a
/// standalone fixture — there is no frozen vector for it — but it is checked by construction: the
/// account id it produces flows into `gatewayAccount`, into the ledger keys, and therefore into
/// `execute`'s public transcript, where the Phase-3.6 PI-vector differential compares it against
/// the compactc artifact element for element.
pub fn owner_commitment<V: Vis3>(c: &mut Circuit3, sk: &B32<V>) -> B32<V> {
    c.region("owner commitment", |c| {
        const DOMAIN: &[u8] = b"aa:manager:owner:v1.0";
        const _: () = assert!(DOMAIN.len() == 21, "the domain literal is a Bytes<21>");
        let tag = {
            let mut le = [0u8; 21];
            le.copy_from_slice(DOMAIN);
            V::from_public(
                c.constant(minocrab::Fr::from_le_bytes(&le).expect("21 bytes fit the field")),
            )
        };
        let alignment = minocrab::Alignment(vec![
            minocrab::AlignmentSegment::Atom(minocrab::AlignmentAtom::Bytes { length: 32 }),
            minocrab::AlignmentSegment::Atom(minocrab::AlignmentAtom::Bytes { length: 21 }),
        ]);
        let inputs = vec![sk.hi.erase(), sk.lo.erase(), tag.erase()];
        let digest = c.persistent_hash(alignment, &inputs);
        B32::from_typed(c, digest)
    })
}

/// `authenticatedNativeAccount(acct)` (`contracts/modules/AccountRegistry.compact:92-97`) — THE single authorization choke
/// point for every native debiting action. Three asserts, in source order.
///
/// Runs under whatever ambient guard the caller's `c.when` scope established.
pub fn authenticated_native_account(
    c: &mut Circuit3,
    acct: &B32<minocrab::Public>,
) -> Uint<8, minocrab::Public> {
    let member = MANAGER.accounts.member(c, acct);
    c.assert(is_true(member).message("caller's owner witness matches no registered account"));

    let has_mode = MANAGER.account_modes.member(c, acct);
    c.assert(is_true(has_mode).message("registered account has no authorization mode"));

    let mode = MANAGER.account_modes.lookup(c, acct);
    c.assert(
        mode.eq(0u64)
            .message("EVM account cannot enter native authorization"),
    );
    mode
}

/// `registerAccount(acct, mode)` (`contracts/modules/AccountRegistry.compact:103-109`) — the shared collision gateway.
/// Three asserts then two inserts, in source order. Runs under the caller's ambient guard.
pub fn register_account(
    c: &mut Circuit3,
    acct: &B32<minocrab::Public>,
    mode: Uint<8, minocrab::Public>,
) {
    let nonzero = b32_is_nonzero(c, acct);
    c.assert(nonzero.message("account id must be nonzero"));

    let already = MANAGER.accounts.member(c, acct);
    c.assert(minocrab_std::v3::not(is_true(already)).message("account already registered"));

    let mode_collision = MANAGER.account_modes.member(c, acct);
    c.assert(minocrab_std::v3::not(is_true(mode_collision)).message("account mode collision"));

    MANAGER.accounts.insert(c, acct);
    MANAGER.account_modes.insert(c, acct, &mode);
}

/// `export circuit isRegistered(owner: Bytes<32>): Boolean` (`contracts/modules/AccountRegistry.compact:121-123`)
///
/// A faithful port: one disclosure, one `Set.member` read against the `accounts` field, the Boolean returned
/// as the circuit's declared output. No guard, no witness, no arithmetic — which is exactly why
/// it is the feasibility probe.
#[circuit(output = "registered")]
pub fn is_registered(c: &mut Circuit3, owner: B32<Private>) -> Discloses<(Owner,), Bool<Public>> {
    let owner = owner.disclose_as::<Owner>(c);
    Discloses::of(MANAGER.accounts.member(c, &owner))
}

/// `export struct AccountRecord` (`contracts/modules/AccountRegistry.compact:57-62`) — the only STRUCT RETURN in the
/// contract's provable surface.
///
/// **Hand-written [`CircuitOut`] and [`Select`], because minocrab has no derive for either.** The
/// field order below IS the output slot order, which the compactc artifact pins:
/// `accountRecord.zkir` declares four `Scalar<BLS12-381>` outputs and ends with
/// `output [%t.2, %t.25, %t.26, %t.27]` — registered, mode, owner, nextNonce. Reordering the
/// fields changes the public schema, which the differential's schema-identity clause catches.
#[derive(Clone, Copy)]
pub struct AccountRecordOut {
    pub registered: Bool<Public>,
    pub mode: Uint<8, Public>,
    pub owner: Bytes<20, Public>,
    pub next_nonce: Uint<64, Public>,
}

impl AccountRecordOut {
    /// `AccountRecord{ registered: false, mode: 0, owner: default<Bytes<20>>, nextNonce: 0 }` —
    /// the all-zero inactive record an unknown account returns.
    fn zero(c: &mut Circuit3) -> Self {
        let z = c.constant(0u64);
        AccountRecordOut {
            registered: Bool::from_field_unchecked(z),
            mode: Uint::from_field_unchecked(z),
            owner: Bytes::from_field_unchecked(z),
            next_nonce: Uint::from_field_unchecked(z),
        }
    }
}

impl CircuitOut for AccountRecordOut {
    const SLOTS: usize = 4;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.registered.field(), &format!("{label} registered"));
        c.output(self.mode.field(), &format!("{label} mode"));
        c.output(self.owner.field(), &format!("{label} owner"));
        c.output(self.next_nonce.field(), &format!("{label} nextNonce"));
    }
}

impl Select<Public> for AccountRecordOut {
    fn select(c: &mut Circuit3, bit: Wire3<FieldT, Public>, taken: Self, fallback: Self) -> Self {
        AccountRecordOut {
            registered: Select::select(c, bit, taken.registered, fallback.registered),
            mode: Select::select(c, bit, taken.mode, fallback.mode),
            owner: Select::select(c, bit, taken.owner, fallback.owner),
            next_nonce: Select::select(c, bit, taken.next_nonce, fallback.next_nonce),
        }
    }
}

/// `export circuit accountRecord(account: Bytes<32>): AccountRecord` (`contracts/modules/AccountRegistry.compact:131-159`)
///
/// ```compact
/// const acct = disclose(account);
/// if (!accounts.member(acct)) { return AccountRecord{false, 0, default, 0}; }
/// const mode = accountModes.lookup(acct);
/// if (mode == 0) {
///   assert(!evmOwners.member(acct) && !evmNonces.member(acct), "native record carries EVM state");
///   return AccountRecord{true, 0, default, 0};
/// }
/// assert(mode == 1, "unknown account authorization mode");
/// assert(evmOwners.member(acct) && evmNonces.member(acct), "EVM record is incomplete");
/// return AccountRecord{true, 1, evmOwners.lookup(acct), evmNonces.lookup(acct)};
/// ```
///
/// Eight ledger reads in the compactc artifact, under five distinct guards, in this order —
/// which is what `pi_skips` equality forces the port to reproduce:
///
/// | # | read | guard |
/// |---:|---|---|
/// | 1 | `accounts.member` | ambient |
/// | 2 | `accountModes.lookup` | `registered` |
/// | 3 | `evmOwners.member` | `registered && mode == 0` |
/// | 4 | `evmNonces.member` | `… && !hasOwner` (short-circuit) |
/// | 5 | `evmOwners.member` | `registered && mode != 0` — a SECOND read |
/// | 6 | `evmNonces.member` | `… && hasOwner` (short-circuit) |
/// | 7 | `evmOwners.lookup` | `registered && mode != 0` |
/// | 8 | `evmNonces.lookup` | `registered && mode != 0` |
///
/// Reads 3 and 5 are the SAME `evmOwners.member(acct)` written twice in the source, once per
/// branch. Compactc compiles both, under different guards; hoisting it to one read would drop an
/// `Impact` and fail `pi_skips` — the `contracts/modules/AccountRegistry.compact:178` precedent from Phase 3.
#[circuit(output = "record")]
pub fn account_record(
    c: &mut Circuit3,
    account: B32<Private>,
) -> Discloses<(Account,), AccountRecordOut> {
    let acct = account.disclose_as::<Account>(c);

    // `if (!accounts.member(acct)) { return <zero record>; }` — the early return is the guard for
    // everything below it.
    let registered = MANAGER.accounts.member(c, &acct);
    let record = c
        .when_value(registered.field(), |c| {
            let mode = MANAGER.account_modes.lookup(c, &acct);
            let is_native = mode.eq(0u64).into_wire(c);

            c.when_value(is_native, |c| {
                // `assert(!evmOwners.member(acct) && !evmNonces.member(acct), …)` — the second
                // read is SHORT-CIRCUITED behind the first, so it is a scope, not a `Check::and`.
                let has_owner = MANAGER.evm_owners.member(c, &acct);
                let no_owner = c.not(has_owner.field());
                let has_nonce = c
                    .when_value(no_owner, |c| MANAGER.evm_nonces.member(c, &acct).field())
                    .otherwise(|c| c.constant(0u64))
                    .into_inner();
                c.assert(
                    not(is_true(has_owner))
                        .and(not(is_true(Bool::from_field_unchecked(has_nonce))))
                        .message("native record carries EVM state"),
                );
                let one = c.constant(1u64);
                let zero = c.constant(0u64);
                AccountRecordOut {
                    registered: Bool::from_field_unchecked(one),
                    mode: Uint::from_field_unchecked(zero),
                    owner: Bytes::from_field_unchecked(zero),
                    next_nonce: Uint::from_field_unchecked(zero),
                }
            })
            .otherwise(|c| {
                c.assert(mode.eq(1u64).message("unknown account authorization mode"));
                // `assert(evmOwners.member(acct) && evmNonces.member(acct), …)` — short-circuited
                // the other way round: the nonce read happens only where the owner read held.
                let has_owner = MANAGER.evm_owners.member(c, &acct);
                let has_nonce = c
                    .when_value(has_owner.field(), |c| {
                        MANAGER.evm_nonces.member(c, &acct).field()
                    })
                    .otherwise(|c| c.constant(0u64))
                    .into_inner();
                c.assert(
                    is_true(has_owner)
                        .and(is_true(Bool::from_field_unchecked(has_nonce)))
                        .message("EVM record is incomplete"),
                );
                let owner = MANAGER.evm_owners.lookup(c, &acct);
                let next_nonce = MANAGER.evm_nonces.lookup(c, &acct);
                let one = c.constant(1u64);
                AccountRecordOut {
                    registered: Bool::from_field_unchecked(one),
                    mode: Uint::from_field_unchecked(one),
                    owner,
                    next_nonce,
                }
            })
            .into_inner()
        })
        .otherwise(AccountRecordOut::zero)
        .into_inner();

    Discloses::of(record)
}

/// `authenticatedActionAccount(p, nativeAccount)` (`contracts/modules/AccountRegistry.compact:171-191`).
///
/// Both arms are compiled; each arm's asserts bind only under its own mode, and the returned
/// account is the `cond_select` of the two. Source order preserved within each arm.
///
/// **Compact's `&&` SHORT-CIRCUITS over ledger reads**, and both arms rely on it:
/// `!evmOwners.member(acct) && !evmNonces.member(acct)` reads `evmNonces` only where the left
/// operand held, and `evmOwners.member(p.account) && evmNonces.member(p.account)` likewise. The
/// compactc artifact guards each second read by the first read's outcome (ops 30-34 and 54-58 of
/// `evidence/00012/raw/00012-p3.4-execute-impact-ops.txt`), so the port does too — a `Check::and`
/// would not, because by the time it runs the read has already been emitted.
///
/// The caller runs this inside `c.when(is_action, …)`; the two mode arms open their own scopes.
///
/// EFFECTS ONLY. Compact's `return acct` / `return p.account` is
/// `cond_select(native_mode, nativeAccount, p.account)`, which is pure compute and is therefore
/// **not** guarded in the artifact — the caller ([`gateway_account`]) computes it outside the
/// scope. Returning it from inside a `when_value` would cost two extra selects compactc does not
/// pay.
pub fn authenticated_action_account_effects(
    c: &mut Circuit3,
    p: &ExecutePayload<Public>,
    native_account: &B32<Public>,
    native_mode: Wire3<FieldT, Public>,
) {
    c.region("auth: action account", |c| {
        c.when(native_mode, |c| {
            // ---- native arm ------------------------------------------------------------------
            crate::account_registry::authenticated_native_account(c, native_account);

            let same = b32_eq(c, native_account, &p.account);
            c.assert(same.message("native witness does not match supplied account transcript"));
            // A SECOND `accountModes.lookup(acct)` — `contracts/modules/AccountRegistry.compact:178` re-reads the cell rather
            // than reusing `authenticatedNativeAccount`'s, and compactc inlines the call, so the
            // artifact carries two identical lookups (ops 17-20 and 21-24). Reusing the first
            // value here would drop an Impact instruction and fail `pi_skips` equality.
            let mode = MANAGER.account_modes.lookup(c, native_account);
            c.assert(
                mode.eq(p.auth_mode)
                    .message("authorization mode does not match account record"),
            );
            let has_owner = MANAGER.evm_owners.member(c, native_account);
            let no_owner = c.not(has_owner.field());
            // A SCOPE, not `member_under(c, no_owner, …)`: see the module docs on F-00012-07 —
            // `_under` mints the read's gates against the AMBIENT guard while emitting the op under
            // `ambient && guard`, so the two diverge and the run consumes a transcript output the
            // reference never produced.
            let has_nonce = c
                .when_value(no_owner, |c| MANAGER.evm_nonces.member(c, native_account))
                .otherwise(|c| Bool::constant(c, false))
                .into_inner();
            c.assert(
                not(is_true(has_owner))
                    .and(not(is_true(has_nonce)))
                    .message("native account carries EVM state"),
            );
        })
        .otherwise(|c| {
            // ---- EVM arm ---------------------------------------------------------------------
            c.assert(
                p.auth_mode
                    .eq(1u64)
                    .message("unknown account authorization mode"),
            );
            let member = MANAGER.accounts.member(c, &p.account);
            c.assert(is_true(member).message("gateway account is not registered"));
            let has_mode = MANAGER.account_modes.member(c, &p.account);
            c.assert(is_true(has_mode).message("registered account has no authorization mode"));
            let mode = MANAGER.account_modes.lookup(c, &p.account);
            c.assert(
                mode.eq(1u64)
                    .message("authorization mode does not match account record"),
            );
            let has_owner = MANAGER.evm_owners.member(c, &p.account);
            let has_nonce = c
                .when_value(has_owner.field(), |c| {
                    MANAGER.evm_nonces.member(c, &p.account)
                })
                .otherwise(|c| Bool::constant(c, false))
                .into_inner();
            c.assert(
                is_true(has_owner)
                    .and(is_true(has_nonce))
                    .message("EVM account record is incomplete"),
            );
            let stored_owner = MANAGER.evm_owners.lookup(c, &p.account);
            c.assert(
                p.owner
                    .eq(stored_owner)
                    .message("signed owner does not match stored owner"),
            );
            let stored_nonce = MANAGER.evm_nonces.lookup(c, &p.account);
            c.assert(p.nonce.eq(stored_nonce).message("EVM nonce mismatch"));
        });
    })
}

/// `gatewayAccount(p, nativeAccount, evmRegistrationAccount)` (`contracts/modules/AccountRegistry.compact:195-207`).
///
/// Selector 0 → the native commitment, selector 1 → the derived EVM registration id, otherwise the
/// authenticated action account. The action arm's ledger reads run under `is_action`, which is the
/// `!s0 && !s1` fall-through of Compact's two early `return`s.
pub fn gateway_account(
    c: &mut Circuit3,
    s: &Selectors,
    p: &ExecutePayload<Public>,
    native_account: &B32<Public>,
    evm_registration_account: &B32<Public>,
) -> B32<Public> {
    let native_mode = p.auth_mode.eq(0u64).into_wire(c);
    c.when(s.is_action, |c| {
        authenticated_action_account_effects(c, p, native_account, native_mode)
    });
    let action_account = B32::cond_select(c, native_mode, native_account, &p.account);
    // s0 ? native : (s1 ? evmRegistration : action)
    let inner = B32::cond_select(c, s.s1, evm_registration_account, &action_account);
    B32::cond_select(c, s.s0, native_account, &inner)
}
