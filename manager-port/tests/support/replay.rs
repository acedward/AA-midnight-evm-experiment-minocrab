//! Q3 bar B — **replay an accepted run through Midnight's own reference VM and ledger.**
//!
//! Bar A compares two artifacts against each other. It never asks whether the transcript they agree
//! on is a program the LEDGER would run: whether the stack discipline holds, whether the `Idx`
//! paths exist, whether each `Popeq`'s embedded result is what the real state would hand back, and
//! whether the declared `Effects` are the ones the ledger would compute. That is what this module
//! adds, using upstream's own driver — [`QueryContext::query`], which owns the
//! `[context, effects, state]` stack convention and the nine-map `Effects` accounting
//! (`onchain-runtime/src/context.rs:922-979`) — exactly as minocrab's own spec suite does
//! (`crates/minocrab-contracts/tests/vault/exec.rs`).
//!
//! ## Where the ops come from
//!
//! Not from a second hand-written model. The bar-A preimage's `public_transcript_inputs` IS the op
//! stream, field-encoded by `Op::<ResultModeVerify>::field_repr`
//! (`onchain-vm/src/ops.rs:460-545`); [`decode_ops`] is that function inverted. Decoding buys two
//! things at once: it proves the derived transcript is a **well-formed op stream** rather than an
//! arbitrary vector of field elements, and it hands the VM the very ops the circuits agreed on —
//! so nothing can drift between what bar A compared and what bar B runs. [`assert_round_trip`]
//! re-encodes and checks the result against the original element for element, so a decoder bug
//! cannot quietly change the program.
//!
//! ## What the replay proves
//!
//! `ResultModeVerify::process_read` checks every `Popeq` against the real state and fails with
//! `ReadMismatch` when the model and the state disagree. So a green replay says: *there exists a
//! real ledger state in which this transcript is exactly what the VM produces* — which is what
//! turns the scenario's hand-written ledger answers from an assertion into a fact.

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value};
use midnight_base_crypto::hash::HashOutput;
use midnight_coin_structure::contract::ContractAddress;
use midnight_onchain_runtime::context::{Effects, QueryContext, QueryResults};
use midnight_onchain_state::state::{ChargedState, StateValue};
use midnight_onchain_vm::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_vm::ops::{Key, Op, VersionedLogItem};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap};
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::fab::AlignmentExt;
use midnight_transient_crypto::repr::FieldRepr;

/// The ledger slot indices, derived from the port's own `#[derive(Ledger)]` block. Imported rather
/// than re-listed so the state array below follows `src/ledger.rs` by construction.
use manager_port::ledger::slot;

pub type VmOp = Op<ResultModeVerify, InMemoryDB>;

// ---- Fr helpers ---------------------------------------------------------------------------------

/// `Fr` as a small non-negative integer, or `None` if it does not fit / is negative.
fn fr_to_u64(f: Fr) -> Option<u64> {
    let le = f.as_le_bytes();
    if le.iter().skip(8).any(|b| *b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    let n = le.len().min(8);
    buf[..n].copy_from_slice(&le[..n]);
    Some(u64::from_le_bytes(buf))
}

/// `Fr` as a small SIGNED integer — the alignment encoding uses `-1` for `Compress`, `-2` for
/// `Field` and `-3` for an `Option` segment, and `Key::Stack` is `-1`.
fn fr_to_i64(f: Fr) -> Option<i64> {
    if let Some(v) = fr_to_u64(f) {
        return i64::try_from(v).ok();
    }
    let neg = Fr::from(0u64) - f;
    fr_to_u64(neg).and_then(|v| i64::try_from(v).ok()).map(|v| -v)
}

// ---- the decoder ---------------------------------------------------------------------------------

struct Cursor<'a> {
    fr: &'a [Fr],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self) -> Result<Fr, String> {
        let f = *self
            .fr
            .get(self.at)
            .ok_or_else(|| format!("op stream ended at element {}", self.at))?;
        self.at += 1;
        Ok(f)
    }

    fn take_i64(&mut self) -> Result<i64, String> {
        let at = self.at;
        let f = self.take()?;
        fr_to_i64(f).ok_or_else(|| format!("element {at} is not a small integer: {f:?}"))
    }

    fn take_u32(&mut self) -> Result<u32, String> {
        let v = self.take_i64()?;
        u32::try_from(v).map_err(|_| format!("element {} is not a u32: {v}", self.at - 1))
    }

    fn done(&self) -> bool {
        self.at >= self.fr.len()
    }
}

fn read_alignment(cur: &mut Cursor) -> Result<Alignment, String> {
    let n = cur.take_u32()?;
    let mut segments = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let at = cur.at;
        let v = cur.take_i64()?;
        let atom = match v {
            -1 => AlignmentAtom::Compress,
            -2 => AlignmentAtom::Field,
            len if len >= 0 => AlignmentAtom::Bytes {
                length: u32::try_from(len).map_err(|_| format!("atom {at}: length {len}"))?,
            },
            other => return Err(format!("atom {at}: unsupported alignment tag {other}")),
        };
        segments.push(AlignmentSegment::Atom(atom));
    }
    Ok(Alignment(segments))
}

fn read_aligned_value(cur: &mut Cursor) -> Result<AlignedValue, String> {
    let alignment = read_alignment(cur)?;
    let want = alignment.field_len();
    let mut limbs = Vec::with_capacity(want);
    for _ in 0..want {
        limbs.push(cur.take()?);
    }
    // `parse_field_repr` is the same routine the simulator and the ledger use to read a FAB value
    // out of field elements, so its result is what makes the decode faithful rather than merely
    // plausible. It pads each atom to its declared width; the VM's own reads are NORMALIZED
    // (`ValueAtom::normalize` strips trailing zeros, and `Alignment::fits` REQUIRES normal form),
    // so a `member` answering false is the empty atom, not a `00` byte. Normalizing here is what
    // makes the decoded op stream compare equal to what `ResultModeVerify` computes.
    let parsed = alignment
        .clone()
        .parse_field_repr(&limbs)
        .ok_or_else(|| format!("limbs do not fit the alignment {alignment:?}"))?;
    let normalized = Value(parsed.value.0.into_iter().map(|a| a.normalize()).collect());
    AlignedValue::new(normalized, alignment)
        .ok_or_else(|| "the normalized value does not fit its alignment".to_string())
}

fn read_state_value(cur: &mut Cursor) -> Result<StateValue, String> {
    let at = cur.at;
    let tag = cur.take_u32()?;
    match tag {
        0 => Ok(StateValue::Null),
        1 => Ok(StateValue::Cell(Sp::new(read_aligned_value(cur)?))),
        t if t & 0xF == 2 => {
            let size = t >> 4;
            let mut m: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
            for _ in 0..size {
                let k = read_aligned_value(cur)?;
                let v = read_state_value(cur)?;
                m = m.insert(k, v);
            }
            Ok(StateValue::Map(m))
        }
        t if t & 0xF == 3 => {
            let n = t >> 4;
            let mut elems = Vec::with_capacity(n as usize);
            for _ in 0..n {
                elems.push(read_state_value(cur)?);
            }
            Ok(StateValue::Array(Array::from(elems)))
        }
        other => Err(format!("element {at}: unsupported StateValue tag {other:#x}")),
    }
}

fn read_key(cur: &mut Cursor) -> Result<Key, String> {
    // `Key::Stack` is the single element `-1`; anything else opens an `AlignedValue`.
    if let Some(f) = cur.fr.get(cur.at) {
        if fr_to_i64(*f) == Some(-1) {
            cur.at += 1;
            return Ok(Key::Stack);
        }
    }
    Ok(Key::Value(read_aligned_value(cur)?))
}

/// `Op::<ResultModeVerify>::field_repr` inverted (`onchain-vm/src/ops.rs:460-545`).
///
/// Adjacent `Noop`s are merged as `prove.rs:291-327` merges them, which is the shape
/// `verify.rs:1889-1894` accepts — a transcript still holding two adjacent `Noop`s is
/// `MalformedTransaction::NotNormalized`.
pub fn decode_ops(transcript: &[Fr]) -> Result<Vec<VmOp>, String> {
    let mut cur = Cursor { fr: transcript, at: 0 };
    let mut ops: Vec<VmOp> = Vec::new();
    while !cur.done() {
        let at = cur.at;
        let b = cur.take_u32().map_err(|e| format!("opcode at {at}: {e}"))?;
        let op = match b {
            0x00 => match ops.last_mut() {
                Some(Op::Noop { n }) => {
                    *n += 1;
                    continue;
                }
                _ => Op::Noop { n: 1 },
            },
            0x01 => Op::Lt,
            0x02 => Op::Eq,
            0x03 => Op::Type,
            0x04 => Op::Size,
            0x05 => Op::New,
            0x06 => Op::And,
            0x07 => Op::Or,
            0x08 => Op::Neg,
            0x09 => Op::Log,
            0x0a => Op::Root,
            0x0b => Op::Pop,
            0x0c | 0x0d => Op::Popeq {
                cached: b == 0x0d,
                result: read_aligned_value(&mut cur)?,
            },
            0x0e => Op::Addi {
                immediate: cur.take_u32()?,
            },
            0x0f => Op::Subi {
                immediate: cur.take_u32()?,
            },
            0x10 | 0x11 => Op::Push {
                storage: b == 0x11,
                value: read_state_value(&mut cur)?,
            },
            0x12 => Op::Branch {
                skip: cur.take_u32()?,
            },
            0x13 => Op::Jmp {
                skip: cur.take_u32()?,
            },
            0x14 => Op::Add,
            0x15 => Op::Sub,
            0x16 | 0x17 => Op::Concat {
                cached: b == 0x17,
                n: cur.take_u32()?,
            },
            0x18 => Op::Member,
            0x19 | 0x1a => Op::Rem { cached: b == 0x1a },
            0x30..=0x3f => Op::Dup { n: (b & 0xf) as u8 },
            0x40..=0x4f => Op::Swap { n: (b & 0xf) as u8 },
            0x50..=0x8f => {
                let (cached, push_path) = match b & 0xf0 {
                    0x50 => (false, false),
                    0x60 => (true, false),
                    0x70 => (false, true),
                    _ => (true, true),
                };
                let len = (b & 0xf) + 1;
                let mut path = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    path.push(read_key(&mut cur)?);
                }
                Op::Idx {
                    cached,
                    push_path,
                    path: path.into(),
                }
            }
            0x90..=0x9f => Op::Ins {
                cached: false,
                n: (b & 0xf) as u8,
            },
            0xa0..=0xaf => Op::Ins {
                cached: true,
                n: (b & 0xf) as u8,
            },
            0xff => Op::Ckpt,
            other => return Err(format!("element {at}: unknown opcode {other:#x}")),
        };
        ops.push(op);
    }
    Ok(ops)
}

/// Re-encode `ops` and check the result against `transcript` element for element — so a decoder bug
/// cannot silently hand the VM a different program from the one bar A compared.
pub fn assert_round_trip(ops: &[VmOp], transcript: &[Fr]) {
    let mut out = Vec::with_capacity(transcript.len());
    for op in ops {
        op.field_repr(&mut out);
    }
    assert_eq!(
        out.len(),
        transcript.len(),
        "the decoded op stream re-encodes to {} elements, not {}",
        out.len(),
        transcript.len()
    );
    for (i, (a, b)) in out.iter().zip(transcript.iter()).enumerate() {
        assert_eq!(a, b, "the decoded op stream differs from the transcript at element {i}");
    }
}

// ---- the pre-state --------------------------------------------------------------------------------

/// The manager's ledger block as real state.
///
/// The *state array* this builds is positional, and the position IS the ledger field index — a
/// mis-numbered read fails at `Popeq` rather than silently reading a neighbour. So [`Self::state`]
/// does not lay the fields out in the order they are declared below: it places each one at
/// `manager_port::ledger::slot::<FIELD>`, derived from the port's own ledger block, which is the
/// same number the emitted `idx` immediates carry. The declaration order here is only the
/// ergonomic one the scenarios were written against and is deliberately left alone; the split
/// contract's slot order (`accounts, accountModes, evmOwners, evmNonces, pools, shieldedBalances,
/// unshieldedBalances, deploymentDomain`) is applied where it matters, in one place.
#[derive(Clone, Debug, Default)]
pub struct PreState {
    /// `pools: Map<Bytes<32>, QualifiedShieldedCoinInfo>` — slot [`slot::POOLS`].
    pub pools: Vec<([u8; 32], AlignedValue)>,
    /// `accounts: Set<Bytes<32>>` (a map with `Null` values) — slot [`slot::ACCOUNTS`].
    pub accounts: Vec<[u8; 32]>,
    /// `shieldedBalances: Map<Bytes<32>, Uint<128>>` — slot [`slot::SHIELDED_BALANCES`].
    pub shielded_balances: Vec<([u8; 32], u128)>,
    /// `unshieldedBalances: Map<Bytes<32>, Uint<128>>` — slot [`slot::UNSHIELDED_BALANCES`].
    pub unshielded_balances: Vec<([u8; 32], u128)>,
    /// `accountModes: Map<Bytes<32>, Uint<8>>` — slot [`slot::ACCOUNT_MODES`].
    pub account_modes: Vec<([u8; 32], u8)>,
    /// `evmOwners: Map<Bytes<32>, Bytes<20>>` — slot [`slot::EVM_OWNERS`].
    pub evm_owners: Vec<([u8; 32], [u8; 20])>,
    /// `evmNonces: Map<Bytes<32>, Uint<64>>` — slot [`slot::EVM_NONCES`].
    pub evm_nonces: Vec<([u8; 32], u64)>,
    /// `deploymentDomain: Bytes<32>` — slot [`slot::DEPLOYMENT_DOMAIN`].
    pub deployment_domain: [u8; 32],
    /// NOT a ledger field: the contract's own **kernel** unshielded balance, per colour. It lives
    /// in `CallContext::balance`, not in the contract's state array, and `kernel.unshieldedBalance`
    /// reads it. Selector 3 (`unshieldedBalanceGte`) is the only path that touches it, so it is
    /// empty for every other scenario. Added by project 00020, whose bar-B replay of selector 3 is
    /// the first accepted run this line has ever had on that path (PR#9 made it provable).
    pub kernel_unshielded_balance: Vec<([u8; 32], u128)>,
}

fn bytesn(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![midnight_base_crypto::fab::ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })]),
    )
    .expect("the bytes fit the atom")
}

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

fn map_of(entries: impl IntoIterator<Item = (AlignedValue, StateValue<InMemoryDB>)>) -> StateValue {
    let mut m: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
    for (k, v) in entries {
        m = m.insert(k, v);
    }
    StateValue::Map(m)
}

impl PreState {
    /// The state array the VM reads, with every field AT ITS LEDGER SLOT.
    ///
    /// Each entry is placed by `slot::<FIELD>` rather than by its position in the `vec!` below, so
    /// the array follows the ledger block in `src/ledger.rs` and cannot fall out of step with the
    /// `idx` immediates the circuits emit. The `expect` fires only if a slot were declared twice
    /// or a field were missing — either of which would be a real bug, not a test artefact.
    pub fn state(&self) -> StateValue {
        let key = |k: &[u8; 32]| bytesn(32, k);
        let placed: Vec<(u8, StateValue)> = vec![
            (
                slot::POOLS,
                map_of(self.pools.iter().map(|(k, v)| (key(k), cell(v.clone())))),
            ),
            (
                slot::ACCOUNTS,
                map_of(self.accounts.iter().map(|k| (key(k), StateValue::Null))),
            ),
            (
                slot::SHIELDED_BALANCES,
                map_of(
                    self.shielded_balances
                        .iter()
                        .map(|(k, v)| (key(k), cell(bytesn(16, &v.to_le_bytes())))),
                ),
            ),
            (
                slot::UNSHIELDED_BALANCES,
                map_of(
                    self.unshielded_balances
                        .iter()
                        .map(|(k, v)| (key(k), cell(bytesn(16, &v.to_le_bytes())))),
                ),
            ),
            (
                slot::ACCOUNT_MODES,
                map_of(
                    self.account_modes
                        .iter()
                        .map(|(k, v)| (key(k), cell(bytesn(1, &[*v])))),
                ),
            ),
            (
                slot::EVM_OWNERS,
                map_of(
                    self.evm_owners
                        .iter()
                        .map(|(k, v)| (key(k), cell(bytesn(20, v)))),
                ),
            ),
            (
                slot::EVM_NONCES,
                map_of(
                    self.evm_nonces
                        .iter()
                        .map(|(k, v)| (key(k), cell(bytesn(8, &v.to_le_bytes())))),
                ),
            ),
            (
                slot::DEPLOYMENT_DOMAIN,
                cell(bytesn(32, &self.deployment_domain)),
            ),
        ];
        let mut fields: Vec<Option<StateValue>> = vec![None; slot::ORDER.len()];
        for (at, value) in placed {
            let cellref = fields
                .get_mut(usize::from(at))
                .expect("a ledger slot outside the block");
            assert!(
                cellref.is_none(),
                "two ledger fields claim slot {at} — src/ledger.rs and this array disagree"
            );
            *cellref = Some(value);
        }
        let fields: Vec<StateValue> = fields
            .into_iter()
            .enumerate()
            .map(|(i, v)| v.unwrap_or_else(|| panic!("ledger slot {i} ({}) unset", slot::ORDER[i])))
            .collect();
        StateValue::Array(Array::from(fields))
    }
}

/// What the reference VM produced for one call.
#[derive(Debug)]
pub struct Executed {
    pub post: StateValue,
    /// The ledger effects the transcript declares — the exact value a transaction's declared
    /// effects are compared against when it is applied.
    pub effects: Effects<InMemoryDB>,
    pub events: Vec<VersionedLogItem<InMemoryDB>>,
}

/// Run `ops` against `pre` with `self_addr` as the contract's own address.
///
/// VERIFY mode, not gather: the ops carry their `Popeq` results, so `process_read` checks each read
/// against the real state and errors `ReadMismatch` when the scenario and the state disagree. That
/// check is the point.
pub fn run(
    pre: &PreState,
    self_addr: &[u8; 32],
    block_time_secs: u64,
    ops: &[VmOp],
) -> Result<Executed, String> {
    let mut ctx = QueryContext::new(
        ChargedState::new(pre.state()),
        ContractAddress(HashOutput(*self_addr)),
    );
    ctx.call_context.tblock = midnight_base_crypto::time::Timestamp::from_secs(block_time_secs);
    for (colour, amount) in &pre.kernel_unshielded_balance {
        ctx.call_context.balance = ctx.call_context.balance.insert(
            midnight_coin_structure::coin::TokenType::Unshielded(
                midnight_coin_structure::coin::UnshieldedTokenType(HashOutput(*colour)),
            ),
            *amount,
        );
    }
    let res: QueryResults<ResultModeVerify, InMemoryDB> = ctx
        .query(ops, None, &INITIAL_COST_MODEL)
        .map_err(|e| format!("{e:?}"))?;
    Ok(Executed {
        post: res.context.state.get_ref().clone(),
        effects: res.context.effects,
        events: res.events,
    })
}

// ---- post-state readers ---------------------------------------------------------------------------

fn field(state: &StateValue, i: usize) -> Option<StateValue> {
    match state {
        StateValue::Array(a) => a.get(i).cloned(),
        _ => None,
    }
}

/// Is `key` present in the map at `field` of `state`?
pub fn map_member(state: &StateValue, i: usize, key: &[u8; 32]) -> bool {
    match field(state, i) {
        Some(StateValue::Map(ref m)) => m.get(&bytesn(32, key)).is_some(),
        _ => false,
    }
}

/// The raw bytes of a `Cell` value in the map at `field` of `state`.
pub fn map_get(state: &StateValue, i: usize, key: &[u8; 32]) -> Option<Vec<u8>> {
    let f = field(state, i)?;
    let StateValue::Map(ref m) = f else {
        return None;
    };
    let entry = m.get(&bytesn(32, key))?;
    let StateValue::Cell(av) = &*entry else {
        return None;
    };
    Some(av.value.0.first()?.0.clone())
}

/// A pooled coin as the ledger stores it: `QualifiedShieldedCoinInfo` under
/// `[bytes 32, bytes 32, bytes 16, bytes 8]`, normalized.
pub fn pool_coin(nonce: &[u8; 32], color: &[u8; 32], value: u128, mt_index: u64) -> AlignedValue {
    use midnight_base_crypto::fab::ValueAtom;
    let atoms = vec![
        ValueAtom(nonce.to_vec()).normalize(),
        ValueAtom(color.to_vec()).normalize(),
        ValueAtom(value.to_le_bytes().to_vec()).normalize(),
        ValueAtom(mt_index.to_le_bytes().to_vec()).normalize(),
    ];
    let alignment = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 16 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 8 }),
    ]);
    AlignedValue::new(Value(atoms), alignment).expect("a well-formed pooled coin")
}

/// A little-endian unsigned integer stored in the map at `field`.
pub fn map_get_uint(state: &StateValue, i: usize, key: &[u8; 32]) -> Option<u128> {
    let bytes = map_get(state, i, key)?;
    let mut le = [0u8; 16];
    le[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
    Some(u128::from_le_bytes(le))
}
