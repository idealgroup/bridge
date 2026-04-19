use alloy_primitives::U256;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::{Transaction, TxOut};

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
/// scalar so the contract can verify using only the internal key:
///   Even y: s' = s - e*t mod n
///   Odd  y: s' = s + e*t mod n
///
/// Returns (adjusted_s, tweaked_key_odd_y).
pub fn compute_adjusted_sig(
    sig_rx: &[u8; 32],
    sig_s: &[u8; 32],
    deposit_tx: &Transaction,
    request_output: &TxOut,
    request_spend_info: &TaprootSpendInfo,
) -> ([u8; 32], bool) {
    let n = SECP256K1_N;

    // Parity of the tweaked output key.
    let odd_y = request_spend_info.output_key_parity() == bitcoin::secp256k1::Parity::Odd;

    // Internal key and merkle root for the taptweak.
    let internal_pk_bytes = request_spend_info.internal_key().serialize();
    let merkle_root_bytes = request_spend_info
        .merkle_root()
        .expect("request output has a script tree")
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
        .expect("sighash computation");

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

    (s_prime.to_be_bytes::<32>(), odd_y)
}
