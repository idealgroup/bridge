use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address};
use starknet::ContractAddress;

use ideal_bridge::minting_contract::{IMintingDispatcher, IMintingDispatcherTrait};

// ERC20 interface for querying the token
#[starknet::interface]
trait IERC20Query<TState> {
    fn total_supply(self: @TState) -> u256;
    fn balance_of(self: @TState, account: ContractAddress) -> u256;
    fn name(self: @TState) -> ByteArray;
    fn symbol(self: @TState) -> ByteArray;
    fn decimals(self: @TState) -> u8;
}

const MINT_DELAY: u64 = 86400;

fn COMMITTEE_PUBKEY() -> u256 {
    0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
}

fn RECIPIENT() -> ContractAddress {
    0x42.try_into().unwrap()
}

fn deploy_contract() -> (ContractAddress, IMintingDispatcher, IERC20QueryDispatcher) {
    let declare_result = declare("MintingContract").expect('declare failed');
    let contract_class = declare_result.contract_class();

    let mut calldata = array![];
    COMMITTEE_PUBKEY().serialize(ref calldata);
    MINT_DELAY.serialize(ref calldata);

    let (addr, _) = contract_class.deploy(@calldata).expect('deploy failed');
    let minting = IMintingDispatcher { contract_address: addr };
    let erc20 = IERC20QueryDispatcher { contract_address: addr };
    (addr, minting, erc20)
}

#[test]
fn test_deploy() {
    let (_addr, _minting, erc20) = deploy_contract();
    assert(erc20.total_supply() == 0, 'total supply should be 0');
    assert(erc20.name() == "Wrapped BTC", 'wrong name');
    assert(erc20.symbol() == "wBTC", 'wrong symbol');
    assert(erc20.decimals() == 8, 'wrong decimals');
}

#[test]
#[should_panic(expected: 'not pending')]
fn test_cancel_with_wrong_secret_no_match() {
    let (_addr, minting, _) = deploy_contract();
    // Cancel with a secret that has no matching pending deposit — status is None
    minting.cancel(0xdeadbeef);
}

#[test]
#[should_panic(expected: 'not pending')]
fn test_mint_nonexistent_deposit() {
    let (_addr, minting, _) = deploy_contract();
    minting.mint(0x1234);
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_burn_no_balance_default_caller() {
    let (_addr, minting, _) = deploy_contract();
    // Default caller has zero balance — burn should fail
    minting.burn(1);
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_burn_without_balance() {
    let (addr, minting, _) = deploy_contract();
    start_cheat_caller_address(addr, RECIPIENT());
    minting.burn(1);
}
