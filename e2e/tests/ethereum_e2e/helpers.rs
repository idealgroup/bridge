use alloy::primitives::Address;
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

/// Convert a 20-byte big-endian Ethereum address to an alloy `Address`.
pub fn bytes_to_address(bytes: &[u8; 20]) -> Address {
    Address::from_slice(bytes)
}
