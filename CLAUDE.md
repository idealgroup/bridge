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
| `withdrawTx` (input 0) | Committee | Per deposit, n variants | `SIGHASH_ALL` |
| `withdrawTx` (input 1) | — | Operator signs at claim time | `SIGHASH_ALL` |

All `SIGHASH_ALL` — every tx is fully determined at sign time. The `kickoffTx` txid is deterministic because the Lamport signature is witness data (doesn't affect txid).

## Architecture Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Script type | Taproot (P2TR) | Key-spend for happy path, script-path leaves for alternatives |
| Lamport hash | `OP_SHA256` (32-byte) | Collision resistance required (operator could forge unusable GC input with 160-bit hash). ~128KB pubkey + ~40KB sig for 256-byte proof |
| Lamport chunking | 3 UTXOs per deposit slot | Tapscript stack limit is 1000 items; per-bit verification peaks at N+2 (OP_DUP + pubkey push), so max 998 bits per script. 2048 bits / 998 = 3 chunks. The `lamport` crate exposes `verification_script_for_range` / `witness_data_for_range`; the `bridge` crate wires chunks to fanout outputs and kickoff inputs. |
| Lamport over Winternitz | Lamport | 1:1 mapping to garbled circuit wire labels |
| BitVM engine | Trait (black box) | GC/SNARK verification out of scope; mock in tests |
| Ethereum interaction | Typed events | No Ethereum deps; clean integration boundary |
| Committee signing | Direct signing functions | `presign_deposit_tx()` / `presign_withdraw_input0()`; MuSig2 aggregation deferred to CLI/server layer |
| Script execution | `BitcoinNetwork` enum | All verification through live bitcoind (`Regtest` mode). Chain monitoring via `broadcast_tx`, `get_raw_transaction`, `get_block_at_height`, `get_chain_tip`, `poll_new_blocks`. |
| Anchor outputs | P2A on `kickoffTx` + `withdrawTx` | Presigned txs need CPFP fee bumping |
| Dust outputs | `DUST_AMOUNT` = 546 sats | For non-value-bearing outputs (fanout, connector, disprove) |
| Timelocks | Relative (`OP_CSV` + `nSequence`) | `cancelTx` uses `OP_CSV` in script; `withdrawTx` connector timelock enforced by `nSequence` committed in committee's presigned input0 |
| Operator coordination | Out of scope | Economic incentive only; no explicit mechanism |
| Actor isolation | Separate clients | Each actor (Operator, Depositor, Committee, Challenger) will run as its own client/process. No shared in-memory state between actors — each must own all data for its workflow or learn it from on-chain data. Tests may share objects for convenience but production code must not assume cross-actor access. |
| Error handling | `Result<T, BridgeError>` | Unified error enum in `lib.rs`. No panics outside tests. |

## Crate Structure

```
ideal-bridge/
├── Cargo.toml                  # workspace
├── lamport/                    # standalone Lamport signature library
│   ├── Cargo.toml
│   └── src/lib.rs              # keygen, sign, bitcoin script verification
├── bridge/                     # main crate
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── params.rs           # configurable constants
│       ├── actor.rs            # Actor types (Operator, Depositor, Committee, Challenger) with key material and transaction orchestration
│       ├── engine.rs           # BitVMEngine trait
│       ├── transactions/       # one module per tx type
│       │   ├── mod.rs          # + flow_tests (end-to-end integration tests)
│       │   ├── fanout.rs
│       │   ├── kickoff.rs
│       │   ├── disprove.rs
│       │   ├── request.rs
│       │   ├── cancel.rs
│       │   ├── deposit.rs
│       │   └── withdraw.rs
│       ├── scripts.rs          # spending condition script builders + P2A helper
│       ├── network.rs          # BitcoinNetwork: Regtest dispatch + chain monitoring
│       └── regtest.rs          # bitcoind regtest node management
```

## Build Order

1. `lamport` — keygen, sign, Bitcoin Script verification, unit tests
2. `params` + `actor` — types and configurable constants
3. `engine` — BitVMEngine trait + mock
4. `scripts` — spending condition script builders
5. `transactions/` — one at a time: fanout -> kickoff -> disprove -> request -> cancel -> deposit -> withdraw
6. `network` + `regtest` — test infrastructure (live bitcoind) + chain monitoring
7. Flow tests in `transactions/mod.rs` — end-to-end deposit + withdrawal cycles

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
