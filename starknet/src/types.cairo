use starknet::ContractAddress;

pub const DUST_AMOUNT: u64 = 546; // Bitcoin dust threshold (sats)

#[derive(Drop, Copy, Serde, starknet::Store, PartialEq)]
pub enum DepositStatus {
    #[default]
    None,
    Pending,
    Minted,
    Cancelled,
}

#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct DepositInfo {
    pub recipient: ContractAddress,
    pub deposit_secret_hash: u256,
    pub request_timestamp: u64,
    pub status: DepositStatus,
    pub amount: u64,
}
