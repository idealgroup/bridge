# Verifying a BIP340 signature against a taproot-tweaked key without EC point addition

## Problem

The `MintingContract` must verify the committee's BIP340 signature on the `depositTx`, but stores only the **internal** key `P`, not the **tweaked** key `Q = P + t·G`. The tweaked key varies per deposit (different cancel script tree per depositor), so it can't be stored as a contract immutable.

Computing `Q = P + t·G` on-chain would require secp256k1 scalar multiplication, but Ethereum has no secp256k1 point arithmetic precompile — `ecAdd`/`ecMul` (0x06/0x07) only support BN254 ([EIP-196](https://eips.ethereum.org/EIPS/eip-196), [EIP-1108](https://eips.ethereum.org/EIPS/eip-1108)). Implementing scalar multiplication in pure Solidity costs ~550k gas. The only cheap secp256k1 operation is `ecrecover` (3000 gas).

Instead, we algebraically eliminate `Q` from the BIP340 equation, reducing verification to a single `ecrecover` against the known internal key `P`.

## Derivation

**BIP340:** `s·G = R + e·Q` where `e = H("BIP0340/challenge", rx || Q.x || m)`.
**BIP341:** `Q = P + t·G` where `t = H("TapTweak", P.x || merkle_root)`.

Substitute Q into the verification equation:

**Even y** (`lift_x(Q.x) = Q`):
```
s·G = R + e·(P + t·G)
(s - e·t)·G = R + e·P
s' = s - e·t mod n
```

**Odd y** (`lift_x(Q.x) = -Q`):
```
s·G = R + e·(-P - t·G)
(s + e·t)·G + e·P = R
s' = s + e·t mod n
```

Both cases reduce to the standard `ecrecover` trick with `P` instead of `Q` and `s'` instead of `s`.

## ecrecover mapping

Setting `R' = P` with `r = P.x`, `v = 27`:

| | `sig_s_param` | `msg_hash_param` |
|---|---|---|
| Even y | `(N - e) · P.x mod N` | `(N - s') · P.x mod N` |
| Odd y | `e · P.x mod N` | `(N - s') · P.x mod N` |

Recovered address must match `address_of(R)`.

## Off-chain / on-chain split

The caller pre-computes `s'` off-chain (see `depositor::adjusted_sig::compute_adjusted_sig`) and provides `(rx, s', tweakedKeyOddY)` to the contract. The contract needs only one `ecrecover` call (3000 gas).

## References

- [BIP340 — Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [ecrecover trick explained](https://hackmd.io/@nZ-twauPRISEa6G9zg3XRw/SyjJzSLt9) — how `ecrecover` is used as a secp256k1 linear combination evaluator
- [EIP-196 — BN254 ecAdd/ecMul precompiles](https://eips.ethereum.org/EIPS/eip-196)
- [EIP-1108 — BN254 precompile gas reduction](https://eips.ethereum.org/EIPS/eip-1108)

