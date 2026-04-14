# Verifying a BIP340 signature against a taproot-tweaked key without EC point addition

## Problem

The `MintingContract` needs to verify that the committee signed the `depositTx`. The committee signs with their **tweaked** key (internal key + cancel script tree), but the contract only stores the **internal** key. Computing the tweaked key on-chain requires secp256k1 point addition, which is expensive in Solidity.

## Solution

Algebraically substitute the BIP341 taptweak into the BIP340 verification equation, eliminating the unknown tweaked key `Q` entirely. The result is verifiable using only the known internal key `P` via the same `ecrecover` trick already used for standard BIP340 verification.

## Derivation

### Starting points

**BIP340 verification.** A signature `(rx, s)` against public key `Q` over message `m` is valid iff:

```
s·G = R + e·Q
```

where `R = lift_x(rx)` and `e = H("BIP0340/challenge", rx || Q.x || m) mod n`.

**BIP341 taptweak.** The tweaked key relates to the internal key via:

```
Q = P + t·G       where t = H("TapTweak", P.x || merkle_root)
```

Both equations are linear in the same elliptic curve group, so one substitutes directly into the other.

### Case A: tweaked point Q has even y

When `Q` has even y, `lift_x(Q.x) = Q = P + t·G`. Substitute into BIP340:

```
s·G = R + e·(P + t·G)
s·G = R + e·P + e·t·G
s·G − e·t·G = R + e·P
(s − e·t)·G = R + e·P
```

Let `s' = s − e·t mod n`:

```
s'·G = R + e·P
```

The right side involves only `P` (the known internal key) and `R` (from the signature). This has the exact same shape as the `ecrecover` trick in `BIP340.sol`, just with `P` instead of `Q` and `s'` instead of `s`.

### Case B: tweaked point Q has odd y

BIP341 defines the x-only output key as `Q.x` regardless of parity. BIP340 verification uses `lift_x(Q.x)`, which always has even y. When the actual `Q = P + t·G` has odd y, `lift_x(Q.x) = −Q = −P − t·G`. Substitute:

```
s·G = R + e·(−P − t·G)
s·G = R − e·P − e·t·G
s·G + e·t·G + e·P = R
(s + e·t)·G + e·P = R
```

Let `s' = s + e·t mod n`:

```
s'·G + e·P = R
```

Same structure as Case A but the signs of `e·t` and `e·P` flip. The caller provides a parity flag (`tweakedKeyOddY`) so the contract uses a single `ecrecover` for the correct case.

### ecrecover mapping

The `ecrecover` precompile computes:

```
ecrecover(hash, v, r, sig_s) → address_of(r⁻¹ · (sig_s · R' − hash · G))
```

where `R'` has x-coordinate `r` and y-parity from `v`.

Setting `R' = P` (v=27, even y) with `r = P.x`:

**Case A** — verify `s'·G − e·P = R`:
- `sig_s_param = (N − e) · P.x mod N`
- `msg_hash_param = (N − s') · P.x mod N`

**Case B** — verify `s'·G + e·P = R`:
- `sig_s_param = e · P.x mod N`
- `msg_hash_param = (N − s') · P.x mod N`

Note that `msg_hash_param = (N − s') · P.x mod N` in both cases — only `sig_s_param` differs by parity.

If the recovered address matches `address_of(R)`, the signature is valid.

## Off-chain vs on-chain split

The caller pre-computes `s'` off-chain (where secp256k1 scalar arithmetic is cheap):
- Compute `t = H("TapTweak", P.x || merkle_root)`
- Recompute the depositTx sighash `m`
- Compute `e = H("BIP0340/challenge", rx || Q.x || m) mod n`
- Even y: `s' = s − e·t mod n`
- Odd  y: `s' = s + e·t mod n`

The caller provides `(rx, s', tweakedKeyOddY)` to the contract. The contract only needs one `ecrecover` call (3000 gas) to verify.

## Security: why a fake tweakedPx fails

The challenge is `e = H(rx || tweakedPx || m)`. If an attacker provides a wrong `tweakedPx`:

1. `e_fake = H(rx || fake || m)`, different from `e_real`
2. The real signature satisfies `s ≡ r + e_real · (p + t) mod n` (scalars)
3. Case A requires `s − e_fake · t ≡ r + e_fake · p mod n`
4. Substituting: `r + e_real·(p+t) − e_fake·t = r + e_fake·p`
5. Simplifying: `(e_real − e_fake) · (p + t) = 0 mod n`
6. Since `p + t ≠ 0` (valid key) and `n` is prime, this requires `e_real = e_fake` — a SHA-256 collision

Case B has the same structure. The verification **implicitly proves the taptweak relationship** without ever computing `Q = P + t·G`.

## Why this works (and is specific to Schnorr)

Schnorr signatures are linear: the verification equation `s·G = R + e·Q` is a linear relation over elliptic curve points. The taptweak `Q = P + t·G` is also linear. Substituting one linear relation into another eliminates the unknown, leaving an equation in known quantities (`P`, `G`, `t`, `R`).

This would **not** work with ECDSA, whose verification equation `s⁻¹·(h·G + r·Q) = R` involves a multiplicative inverse of `s`, making it nonlinear in the signature components.
