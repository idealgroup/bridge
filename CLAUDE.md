# ideal-bridge

A Rust implementation of a BitVM3 bridge between Bitcoin and Ethereum.
Designed as a clean, testable library that can be integrated into a CLI/server by another team.

## Protocol Overview

The bridge enables BTC <-> wBTC (on Ethereum) transfers using an optimistic protocol
with one-round fraud proofs via garbled circuits.

### Deposit Flow (BTC -> wBTC)
1. Depositor locks 1 BTC in `requestTx` — spendable by the committee OR by the depositor after timeout (revealing `depositSecret`)
2. Committee presigns `depositTx`, moving the BTC under committee control
3. On Ethereum, wBTC is minted after Bitcoin finality
4. If anything goes wrong, depositor can reclaim via `cancelTx` (reveals `depositSecret`, which also cancels the L2 mint)

### Withdrawal Flow (wBTC -> BTC)
1. User burns wBTC on Ethereum
2. Operator posts `kickoffTx` — consumes 3 fanout leaf UTXOs (one per Lamport chunk) and commits a 256-byte SNARK proof via Lamport signature across the 3 inputs
3. Challenge period: anyone can evaluate the garbled circuit; if the proof is invalid, the GC reveals a wire label (the `disproveSecret`) that allows spending via `disproveTx`, burning the connector and blocking withdrawal
4. After timeout, operator claims via `withdrawTx` (two inputs: deposit UTXO presigned by committee + surviving connector)

### Transaction Graph
```
                       fanoutTx  --+-- leaf₀ --\
                                   +-- leaf₁ ---+--> kickoffTx  -->  disproveTx (fraud proof burns connector)
                                   +-- leaf₂ --/         |
                                                         +-- connector survives --> withdrawTx (operator claims)
                                                                                       ^
requestTx  -->  depositTx  ------------------------------------------------------------+
       |
       +------->  cancelTx (depositor escape hatch)
```
- `requestTx` output is spent by EITHER `depositTx` (happy path) OR `cancelTx` (escape hatch), never both
- `kickoffTx` consumes 3 fanout leaf UTXOs (one per Lamport chunk), forcing full proof reveal
- `withdrawTx` consumes two inputs: one from `depositTx` and one from `kickoffTx`
- `kickoffTx` connector is spent by EITHER `disproveTx` (fraud) OR `withdrawTx` (happy path)

The `fanoutTx` forms a tree of depth `L` with branching factor `m`, expanding from each operator's `initUtxo`. Leaf-level transactions produce **3 outputs per deposit slot** (one per Lamport chunk), for a total of `DEPOSIT_COUNT * 3` leaf UTXOs per operator. The 3-output grouping is an implementation detail driven by the tapscript 1000 stack item limit (max 998 Lamport bits per script; `ceil(2048/998)` = 3 chunks for a 256-byte proof). The fanout tree depth/branching is a separate concern about efficiently expanding one UTXO into many.

Each `kickoffTx` consumes one triple of fanout leaf UTXOs (3 inputs), forcing the operator to reveal all 3 Lamport signature chunks — i.e. the full 256-byte SNARK proof. There are `DEPOSIT_COUNT` kickoffTxs per operator. Lamport keypairs for each leaf are isomorphic to garbled circuit wire labels — the signature scheme and the fraud proof mechanism share key material.

### Actors
- **Committee** (n-of-n): presigns deposit and withdraw transactions. Static signer set. Must be online for new deposits.
- **Operators** (`1..n`): front withdrawals, post proofs, claim deposits after timeout. Not involved in deposit presigning.
- **Depositors** (`1..DEPOSIT_COUNT`): lock BTC, receive wBTC on Ethereum.
- **Challengers** (permissionless): verify proofs, submit disprove transactions if fraud detected.

### Presigning Model

| Transaction | Who presigns | When | Sighash |
|---|---|---|---|
| `fanoutTx` | — | Operator signs at will | `SIGHASH_ALL` |
| `kickoffTx` | — | Operator signs at claim time | `SIGHASH_ALL` |
| `disproveTx` | — | Hash preimage, no sig | — |
| `requestTx` | — | Depositor signs at deposit time | `SIGHASH_ALL` |
| `cancelTx` | — | Depositor signs if cancelling | `SIGHASH_ALL` |
| `depositTx` | Committee | Per deposit | `SIGHASH_ALL` |
| `withdrawTx` (input 0) | Committee | Per deposit, n variants | `SIGHASH_SINGLE` |
| `withdrawTx` (input 1) | — | Operator signs at claim time | `SIGHASH_ALL` |

All `SIGHASH_ALL` except `withdrawTx` input 0 which uses `SIGHASH_SINGLE` — this commits to the OP_RETURN at output 0 while letting the operator choose additional outputs (and fees) at broadcast time. All inputs (outpoints, amounts, scriptPubKeys, sequences) are still committed per BIP 341, preserving the connector timelock. The `kickoffTx` txid is deterministic because the Lamport signature is witness data (doesn't affect txid).

## Architecture Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Script type | Taproot (P2TR) | Key-spend for happy path, script-path leaves for alternatives |
| Lamport hash | `OP_SHA256` (32-byte) | Collision resistance required (operator could forge unusable GC input with 160-bit hash). ~128KB pubkey + ~40KB sig for 256-byte proof |
| Lamport chunking | 3 UTXOs per deposit slot | Tapscript stack limit is 1000 items; per-bit verification peaks at N+2 (OP_DUP + pubkey push), so max 998 bits per script. 2048 bits / 998 = 3 chunks. The `lamport` crate exposes `verification_script_for_range` / `witness_data_for_range`; `operator/` wires chunks to fanout outputs and kickoff inputs. |
| Lamport over Winternitz | Lamport | 1:1 mapping to garbled circuit wire labels |
| BitVM engine | Trait (black box) | GC/SNARK verification out of scope; mock in tests |
| Ethereum interaction | Typed events | No Ethereum deps; clean integration boundary |
| Committee signing | Direct signing functions | `committee/deposit.rs` and `committee/withdraw.rs`; MuSig2 aggregation deferred to CLI/server layer |
| Script execution | `BitcoinNetwork` enum | All verification through live bitcoind (`Regtest` mode). Chain monitoring via `broadcast_tx`, `get_raw_transaction`, `get_block_at_height`, `get_chain_tip`, `poll_new_blocks`. |
| Anchor outputs | Operator-keyed P2TR anchor on `kickoffTx` only | `kickoffTx` anchor is operator-keyed (prevents replacement cycling). `depositTx` has no anchor (fee set at presign time). `withdrawTx` uses `SIGHASH_SINGLE` on input 0 with OP_RETURN at output 0 (operator sets fee via additional outputs) |
| Dust outputs | `DUST_AMOUNT` = 546 sats | For non-value-bearing outputs (fanout, connector, disprove) |
| Timelocks | Relative (`OP_CSV` + `nSequence`) | `cancelTx` uses `OP_CSV` in script; `withdrawTx` connector timelock enforced by `nSequence` committed in committee's presigned input0 |
| Operator coordination | Out of scope | Economic incentive only; no explicit mechanism |
| Actor isolation | Separate crates + clients | Each actor (Operator, Depositor, Committee, Challenger) has its own crate with tx build/sign logic and a Client struct. `bridge/` is a thin shared-types layer. No shared in-memory state between actors — each must own all data for its workflow or learn it from on-chain data. |
| Error handling | `Result<T, BridgeError>` | Unified error enum in `lib.rs`. No panics outside tests. |

## Crate Structure

```
ideal-bridge/
├── Cargo.toml                  # workspace
├── lamport/                    # standalone Lamport signature library
│   ├── Cargo.toml
│   └── src/lib.rs              # keygen, sign, bitcoin script verification
├── bridge/                     # shared types, scripts, infrastructure (no tx building)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # BridgeError enum
│       ├── params.rs           # configurable constants
│       ├── actor.rs            # data-only actor structs (Operator, Depositor, Committee, Challenger) — key material + constructors, no tx methods
│       ├── engine.rs           # BitVMEngine trait + MockEngine
│       ├── scripts.rs          # spending condition script builders
│       ├── test_support.rs     # shared test helpers (test_rng, dummy_outpoint)
│       ├── network.rs          # BitcoinNetwork: Regtest dispatch + chain monitoring
│       └── regtest.rs          # bitcoind regtest node management
├── committee/                  # committee signing client (presigns deposit + withdraw)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs              # CommitteeClient: presign_deposit, presign_withdraw
│   │   ├── deposit.rs          # build_deposit_tx, presign_deposit_tx
│   │   ├── withdraw.rs         # build_withdraw_tx, presign_withdraw_input0
│   │   └── main.rs             # placeholder
├── operator/                   # operator client (fanout, kickoff, withdraw completion)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs              # OperatorClient: create_fanout_tree, create_kickoff, complete_withdraw
│   │   ├── fanout.rs           # FanoutTree struct + build_fanout_tree, sign_fanout_tree
│   │   ├── kickoff.rs          # build_kickoff_tx, sign_kickoff_tx
│   │   ├── withdraw.rs         # sign_withdraw_input1
│   │   └── main.rs             # placeholder
│   └── tests/integration.rs    # 2 tests: fanout+kickoff, wrong lamport rejected
├── depositor/                  # depositor client (request, cancel)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs              # DepositorClient: create_request, create_cancel
│   │   ├── request.rs          # build_request_tx, sign_request_tx
│   │   ├── cancel.rs           # build_cancel_tx, sign_cancel_tx
│   │   └── main.rs             # placeholder
│   └── tests/integration.rs    # 3 tests: request, cancel, cancel-before-timeout rejected
├── challenger/                 # challenger monitoring client (disprove + kickoff parsing)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs              # ChallengerClient<E>: challenge_kickoff, scan_block_for_kickoffs
│   │   ├── kickoff.rs          # KickoffData + extract_proof_from_kickoff (witness parsing)
│   │   ├── disprove.rs         # build_disprove_tx, witness_disprove_tx
│   │   └── main.rs             # placeholder
├── e2e/                        # end-to-end integration tests across all actor clients
│   ├── Cargo.toml
│   └── tests/e2e.rs            # 5 tests: happy path withdraw, cancel escape hatch, fraud proof disprove, ignore valid proof, extract proof from kickoff
```

### Transaction Ownership

Each actor crate owns the build/sign logic for the transactions it creates:

| Transaction | Owner crate | Functions |
|---|---|---|
| `requestTx` | `depositor/` | `build_request_tx`, `sign_request_tx` |
| `cancelTx` | `depositor/` | `build_cancel_tx`, `sign_cancel_tx` |
| `fanoutTx` | `operator/` | `build_fanout_tree`, `sign_fanout_tree` |
| `kickoffTx` | `operator/` | `build_kickoff_tx`, `sign_kickoff_tx` |
| `withdrawTx` (input 1) | `operator/` | `sign_withdraw_input1` |
| `depositTx` | `committee/` | `build_deposit_tx`, `presign_deposit_tx` |
| `withdrawTx` (build + input 0) | `committee/` | `build_withdraw_tx`, `presign_withdraw_input0` |
| `disproveTx` | `challenger/` | `build_disprove_tx`, `witness_disprove_tx` |

## Build Order

1. `lamport` — keygen, sign, Bitcoin Script verification, unit tests
2. `bridge` — shared types: `params`, `actor` (data-only), `engine`, `scripts`, `transactions/fanout` + `transactions/kickoff` (shared types only), `network` + `regtest`
3. Actor crates (each depends on `bridge`): `committee`, `operator`, `depositor`, `challenger`
4. `e2e` — end-to-end integration tests across all actor clients

## Parameters (defaults)

- `DEPOSIT_SIZE`: 1 BTC
- `DEPOSIT_COUNT`: 10,000
- `OPERATOR_COUNT` (`n`): 50
- `COMMITTEE_SIZE`: 10 signers (n-of-n)
- `LAMPORT_CHUNKS_PER_SLOT`: 3 (derived: `ceil(2048/998)`)
- `FANOUT_BRANCHING` (`m`): 10
- `FANOUT_DEPTH` (`L`): derived as `ceil(log_m(DEPOSIT_COUNT))` = 4. Total leaf UTXOs = `DEPOSIT_COUNT * 3` = 30,000 (how deposit slots are packed into leaf-level txs is an optimization detail).
- `KICKOFF_TIMEOUT`: 3 days (relative, enforced by `nSequence`)
- `DEPOSIT_TIMEOUT`: 1 hour (relative, `OP_CSV`)
- `PROOF_SIZE`: 256 bytes (Groth16 / BN254)
- `DUST_AMOUNT`: 546 sats

## Code Style

- Keep it slim. Minimal abstractions. No premature generalization.
- Tests for every module. Tests ARE the executable spec.
- Succinct inline comments only where the logic isn't self-evident.
- CLAUDE.md is the single source of truth for architecture.
- `rust-bitcoin` for all Bitcoin primitives. Rust edition 2021.
- All fallible functions return `Result<T, BridgeError>`. No panics outside tests.
