use alloy::primitives::Address;

/// Convert a 20-byte big-endian Ethereum address to an alloy `Address`.
pub fn bytes_to_address(bytes: &[u8; 20]) -> Address {
    Address::from_slice(bytes)
}
