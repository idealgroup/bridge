use alloy_primitives::U256;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::{Transaction, TxOut};

use bridge::BridgeError;

/// secp256k1 group order n.
const SECP256K1_N: U256 = U256::from_be_bytes([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x41,
]);

/// BIP340/BIP341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute the pre-adjusted BIP340 signature scalar `s'` and parity flag for
/// on-chain verification against the committee's internal (untweaked) key.
///
/// The committee signs the depositTx with their taproot-tweaked key
/// (internal key + cancel script tree). This function adjusts the signature
/// scalar so the contract can verify using only the internal key.
///
/// ## Derivation
///
/// BIP340 verification: `s·G = R + e·Q` where `e = H("BIP0340/challenge", rx || Q.x || m)`.
/// BIP341 taptweak: `Q = P + t·G` where `t = H("TapTweak", P.x || merkle_root)`.
///
/// Substituting Q into the verification equation:
///
/// **Even y** (`lift_x(Q.x) = Q`):
///   `s·G = R + e·(P + t·G)` → `(s - e·t)·G = R + e·P` → **`s' = s - e·t mod n`**
///
/// **Odd y** (`lift_x(Q.x) = -Q = -P - t·G`):
///   `s·G = R + e·(-P - t·G)` → `(s + e·t)·G = R - e·P` → **`s' = s + e·t mod n`**
///
/// The resulting equation has the same shape as standard BIP340 but with the
/// internal key `P` instead of the tweaked key `Q`, so the contract can verify
/// with a single `ecrecover` call. See `docs/verify_tweaked_sig.md` for the
/// full derivation including the ecrecover mapping and security argument.
///
/// Returns (adjusted_s, tweaked_key_odd_y).
pub fn compute_adjusted_sig(
    sig_rx: &[u8; 32],
    sig_s: &[u8; 32],
    deposit_tx: &Transaction,
    request_output: &TxOut,
    request_spend_info: &TaprootSpendInfo,
) -> Result<([u8; 32], bool), BridgeError> {
    let n = SECP256K1_N;

    // Parity of the tweaked output key.
    let odd_y = request_spend_info.output_key_parity() == bitcoin::secp256k1::Parity::Odd;

    // Internal key and merkle root for the taptweak.
    let internal_pk_bytes = request_spend_info.internal_key().serialize();
    let merkle_root_bytes = request_spend_info
        .merkle_root()
        .ok_or(BridgeError::MissingData("request spend info merkle root"))?
        .to_byte_array();

    // t = H("TapTweak", internalPx || merkleRoot) mod n
    let mut t_preimage = Vec::with_capacity(64);
    t_preimage.extend_from_slice(&internal_pk_bytes);
    t_preimage.extend_from_slice(&merkle_root_bytes);
    let t = U256::from_be_bytes(tagged_hash("TapTweak", &t_preimage)) % n;

    // Recompute the depositTx sighash (same as what the committee signed).
    let prevouts = [request_output.clone()];
    let sighash = SighashCache::new(deposit_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .map_err(BridgeError::Sighash)?;

    // e = H("BIP0340/challenge", rx || tweakedPx || sighash) mod n
    let tweaked_pk_bytes = request_spend_info.output_key().serialize();
    let mut e_preimage = Vec::with_capacity(96);
    e_preimage.extend_from_slice(sig_rx);
    e_preimage.extend_from_slice(&tweaked_pk_bytes);
    e_preimage.extend_from_slice(sighash.as_byte_array());
    let e = U256::from_be_bytes(tagged_hash("BIP0340/challenge", &e_preimage)) % n;

    // s' = s +/- e*t mod n
    let s = U256::from_be_bytes(*sig_s);
    let et = e.mul_mod(t, n);
    let s_prime = if odd_y {
        s.add_mod(et, n)
    } else {
        s.add_mod(n - et, n)
    };

    Ok((s_prime.to_be_bytes::<32>(), odd_y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::transaction::{TxIn, Version};
    use bitcoin::{OutPoint, ScriptBuf, Txid, Witness};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use bridge::actor::{Committee, Depositor};
    use bridge::params::Params;
    use bridge::scripts;

    /// Demonstrates the adjusted-signature trick: the committee signs the
    /// depositTx with their *tweaked* key, but after adjustment the signature
    /// verifies against the *internal* (untweaked) key.
    #[test]
    fn test_adjusted_sig_verifies_against_internal_key() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        let depositor = Depositor::new(
            &mut rng,
            &secp,
            0,
            bridge::test_support::dummy_outpoint(),
        );
        let committee = Committee::new(&mut rng, &secp);

        // Build the request spend info (committee key + cancel script tree).
        let request_spend_info = scripts::request_spend_info(
            &secp,
            committee.pubkey,
            depositor.pubkey,
            depositor.deposit_secret_hash(),
            params.deposit_timeout,
        )
        .unwrap();

        // Build a minimal depositTx (only need the structure for sighash).
        let deposit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: params.deposit_size,
                script_pubkey: ScriptBuf::new_p2tr(&secp, committee.pubkey, None),
            }],
        };

        // The request output that the depositTx spends.
        let request_output = TxOut {
            value: params.request_input_value(),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(request_spend_info.output_key()),
        };

        // Sign the depositTx with the committee's tweaked key (as in presigning).
        let tweaked_kp = committee.keypair.tap_tweak(&secp, request_spend_info.merkle_root());
        let sighash = SighashCache::new(&deposit_tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[request_output.clone()]),
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest(*sighash.as_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_kp.to_keypair());
        let sig_bytes = sig.serialize();

        // Standard BIP340 verification passes against the *tweaked* key.
        let tweaked_pk = request_spend_info.output_key().to_x_only_public_key();
        secp.verify_schnorr(&sig, &msg, &tweaked_pk).unwrap();

        // Standard BIP340 verification *fails* against the internal key.
        assert!(secp.verify_schnorr(&sig, &msg, &committee.pubkey).is_err());

        // Compute the adjusted s' so the contract can verify against the internal key.
        let (adjusted_s, odd_y) = compute_adjusted_sig(
            sig_bytes[..32].try_into().unwrap(),
            sig_bytes[32..].try_into().unwrap(),
            &deposit_tx,
            &request_output,
            &request_spend_info,
        )
        .unwrap();

        // Verify the algebraic relationship: reversing the adjustment on s'
        // must recover the original s, proving s'·G = R ± e·P holds.
        let n = SECP256K1_N;

        // e = H("BIP0340/challenge", rx || tweakedPx || sighash) mod n
        let tweaked_pk_bytes = request_spend_info.output_key().serialize();
        let mut e_preimage = Vec::with_capacity(96);
        e_preimage.extend_from_slice(&sig_bytes[..32]);
        e_preimage.extend_from_slice(&tweaked_pk_bytes);
        e_preimage.extend_from_slice(sighash.as_byte_array());
        let e = U256::from_be_bytes(tagged_hash("BIP0340/challenge", &e_preimage)) % n;

        // t = H("TapTweak", P.x || merkleRoot) mod n
        let internal_pk_bytes = request_spend_info.internal_key().serialize();
        let merkle_root_bytes = request_spend_info.merkle_root().unwrap().to_byte_array();
        let mut t_preimage = Vec::with_capacity(64);
        t_preimage.extend_from_slice(&internal_pk_bytes);
        t_preimage.extend_from_slice(&merkle_root_bytes);
        let t = U256::from_be_bytes(tagged_hash("TapTweak", &t_preimage)) % n;
        let et = e.mul_mod(t, n);

        let s_prime = U256::from_be_bytes(adjusted_s);
        let s_original = U256::from_be_bytes::<32>(sig_bytes[32..].try_into().unwrap());

        // Round-trip: reversing the parity-dependent adjustment recovers s.
        let recovered_s = if odd_y {
            s_prime.add_mod(n - et, n) // reverse of s' = s + e·t
        } else {
            s_prime.add_mod(et, n) // reverse of s' = s - e·t
        };
        assert_eq!(recovered_s, s_original, "round-trip s' -> s failed");
    }
}
