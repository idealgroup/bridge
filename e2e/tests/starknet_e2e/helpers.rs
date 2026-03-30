use bitcoin::consensus;
use bitcoin::transaction::Transaction;
use starknet::core::types::Felt;

/// Serialize a Bitcoin transaction in non-witness format (for Cairo txid computation).
/// Clones the tx, clears all witnesses, then serializes using legacy (non-segwit) format.
pub fn serialize_tx_no_witness(tx: &Transaction) -> Vec<u8> {
    let mut tx_clone = tx.clone();
    for input in &mut tx_clone.input {
        input.witness = bitcoin::Witness::new();
    }
    consensus::serialize(&tx_clone)
}

/// Encode a byte slice as Cairo ByteArray ABI calldata.
///
/// Cairo ByteArray layout:
///   [num_full_31byte_words, word0, word1, ..., pending_word, pending_word_len]
///
/// Each "full word" is 31 bytes, packed big-endian into a felt252.
/// The "pending word" contains the remaining bytes (0-30), also big-endian.
pub fn bytes_to_bytearray_calldata(data: &[u8]) -> Vec<Felt> {
    let full_words = data.len() / 31;
    let pending_len = data.len() % 31;

    let mut calldata = vec![Felt::from(full_words as u64)];

    // Full 31-byte words
    for i in 0..full_words {
        let chunk = &data[i * 31..(i + 1) * 31];
        let felt = felt_from_be_bytes(chunk);
        calldata.push(felt);
    }

    // Pending word (remaining bytes)
    if pending_len > 0 {
        let pending = &data[full_words * 31..];
        calldata.push(felt_from_be_bytes(pending));
    } else {
        calldata.push(Felt::ZERO);
    }
    calldata.push(Felt::from(pending_len as u64));

    calldata
}

/// Convert 32 bytes to (low, high) Felt pair for u256 ABI.
/// low = bytes[16..32] as big-endian u128
/// high = bytes[0..16] as big-endian u128
pub fn bytes32_to_u256_felts(bytes: &[u8; 32]) -> (Felt, Felt) {
    let mut high_bytes = [0u8; 16];
    let mut low_bytes = [0u8; 16];
    high_bytes.copy_from_slice(&bytes[0..16]);
    low_bytes.copy_from_slice(&bytes[16..32]);

    let high = u128::from_be_bytes(high_bytes);
    let low = u128::from_be_bytes(low_bytes);
    (Felt::from(low), Felt::from(high))
}

/// Split a 64-byte BIP340 Schnorr signature into (rx_low, rx_high, s_low, s_high).
pub fn schnorr_sig_to_felts(sig: &[u8; 64]) -> (Felt, Felt, Felt, Felt) {
    let mut rx = [0u8; 32];
    let mut s = [0u8; 32];
    rx.copy_from_slice(&sig[0..32]);
    s.copy_from_slice(&sig[32..64]);
    let (rx_low, rx_high) = bytes32_to_u256_felts(&rx);
    let (s_low, s_high) = bytes32_to_u256_felts(&s);
    (rx_low, rx_high, s_low, s_high)
}

/// Convert a u64 value to (low, high) Felt pair for u256 ABI.
pub fn u64_to_u256_felts(v: u64) -> (Felt, Felt) {
    (Felt::from(v), Felt::ZERO)
}

/// Pack big-endian bytes into a Felt.
fn felt_from_be_bytes(bytes: &[u8]) -> Felt {
    assert!(bytes.len() <= 31, "felt252 max 31 bytes");
    // Pad to 32 bytes with leading zeros
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    Felt::from_bytes_be(&padded)
}
