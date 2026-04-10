use alloy::primitives::{Address, B256};
use bitcoin::consensus;
use bitcoin::transaction::Transaction;

/// Serialize a Bitcoin transaction in non-witness (legacy) format so the Solidity
/// `TxParser` can compute the txid by double-SHA256 over the byte string.
pub fn serialize_tx_no_witness(tx: &Transaction) -> Vec<u8> {
    let mut tx_clone = tx.clone();
    for input in &mut tx_clone.input {
        input.witness = bitcoin::Witness::new();
    }
    consensus::serialize(&tx_clone)
}

/// Split a 64-byte BIP340 Schnorr signature into its (rx, s) components.
pub fn schnorr_sig_to_bytes32_pair(sig: &[u8; 64]) -> (B256, B256) {
    let mut rx = [0u8; 32];
    let mut s = [0u8; 32];
    rx.copy_from_slice(&sig[0..32]);
    s.copy_from_slice(&sig[32..64]);
    (B256::from_slice(&rx), B256::from_slice(&s))
}

/// Convert a 20-byte big-endian Ethereum address to an alloy `Address`.
pub fn bytes_to_address(bytes: &[u8; 20]) -> Address {
    Address::from_slice(bytes)
}
