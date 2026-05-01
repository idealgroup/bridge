# BitVM3-Bridge

A Rust implementation of BitVM3-BRIDGE, a trust-minimized bridge between Bitcoin and chains with finality certificates (e.g., Ethereum) or Bitcoin rollups.

The bridge is powered by BitVM3-CORE, a modular abstraction for permissionless off-chain computation on Bitcoin using garbled circuits. Disputes settle in two on-chain rounds with a fraud proof costing less than $0.20.

## Setup

### Option A: Nix (recommended)

[Install Nix](https://nixos.org/download/) with flakes enabled, then:

```bash
nix develop
```

This drops you into a shell with the Rust toolchain, `bitcoind`, and all dependencies.

### Option B: Manual

Install the following yourself:
- [Rust](https://rustup.rs/) (edition 2021)
- [Bitcoin Core](https://bitcoincore.org/en/download/) (`bitcoind` must be in your `PATH`)

## Build and Test

```bash
cargo build --workspace
cargo test --workspace
```

The test suite spawns ephemeral `bitcoind` regtest nodes automatically — no manual setup required.

## Crate Structure

| Crate | Description |
|---|---|
| `lamport/` | Standalone Lamport one-time signature library with Bitcoin Script verification |
| `bridge/` | Shared types, spending-condition scripts, params, and regtest infrastructure |
| `committee/` | Committee signing: presigns deposit and withdraw transactions |
| `operator/` | Operator: fanout tree, kickoff, withdraw completion |
| `depositor/` | Depositor: request and cancel transactions |
| `challenger/` | Challenger: monitors kickoffs, builds disprove transactions |
| `e2e/` | End-to-end integration tests across all actor clients |

## Architecture

The implementation is generic over the garbled-circuit backend via the `BitVMEngine` trait. Tests use a mock engine; any concrete garbling scheme (e.g., the [BitVM Alliance Groth16 verifier](https://github.com/BitVM/garbled-snark-verifier)) can be plugged in.

See `CLAUDE.md` for detailed architecture documentation.
