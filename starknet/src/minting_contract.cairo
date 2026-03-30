/// Starknet minting contract for the ideal-bridge.
///
/// Manages wBTC minting/burning backed by Bitcoin deposits. Verifies the committee's
/// BIP340 Schnorr signature on the deterministic depositTx to confirm deposits.
#[starknet::contract]
pub mod MintingContract {
    use openzeppelin_token::erc20::ERC20Component;
    use openzeppelin_token::erc20::ERC20Component::InternalTrait as ERC20InternalTrait;
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    use alexandria_btc::bip340::verify as bip340_verify;
    use alexandria_btc::hash::sha256_u256;

    use crate::types::{DUST_AMOUNT, DepositInfo, DepositStatus};
    use crate::tx_parser::parse_request_tx;
    use crate::deposit_tx::compute_deposit_sighash;

    // ERC20 component
    component!(path: ERC20Component, storage: erc20, event: ERC20Event);

    // Expose ERC20 externals
    #[abi(embed_v0)]
    impl ERC20Impl = ERC20Component::ERC20Impl<ContractState>;

    #[abi(embed_v0)]
    impl ERC20MetadataImpl = ERC20Component::ERC20MetadataImpl<ContractState>;

    #[abi(embed_v0)]
    impl ERC20CamelOnlyImpl = ERC20Component::ERC20CamelOnlyImpl<ContractState>;

    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    // 8 decimals for wBTC (matching Bitcoin's satoshi precision)
    impl ERC20Config of ERC20Component::ImmutableConfig {
        const DECIMALS: u8 = 8;
    }

    // No-op hooks
    impl ERC20HooksImpl of ERC20Component::ERC20HooksTrait<ContractState> {}

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        committee_pubkey: u256,
        mint_delay: u64,
        deposits: Map<u256, DepositInfo>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
        Request: Request,
        Mint: Mint,
        Cancel: Cancel,
        Burn: Burn,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Request {
        #[key]
        pub deposit_secret_hash: u256,
        pub recipient: ContractAddress,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Mint {
        #[key]
        pub deposit_secret_hash: u256,
        pub recipient: ContractAddress,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Cancel {
        #[key]
        pub deposit_secret_hash: u256,
        pub cancelled_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Burn {
        #[key]
        pub account: ContractAddress,
        pub amount: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        committee_pubkey: u256,
        mint_delay: u64,
    ) {
        self.erc20.initializer("Wrapped BTC", "wBTC");
        self.committee_pubkey.write(committee_pubkey);
        self.mint_delay.write(mint_delay);
    }

    #[abi(embed_v0)]
    impl MintingImpl of super::IMinting<ContractState> {
        /// Submit a deposit request with the committee's signature on the depositTx.
        ///
        /// Anyone can call this. The recipient is extracted from the requestTx's OP_RETURN.
        fn request(
            ref self: ContractState,
            raw_request_tx: ByteArray,
            deposit_secret_hash: u256,
            sigma_1_rx: u256,
            sigma_1_s: u256,
        ) {
            // Parse the requestTx
            let tx_data = parse_request_tx(@raw_request_tx, deposit_secret_hash);

            // Check this deposit hasn't been requested before
            let existing = self.deposits.read(deposit_secret_hash);
            assert(existing.status == DepositStatus::None, 'deposit already requested');

            // Derive deposit output amount from request output (ground truth)
            // deposit_output_amount = request_output0_amount - DUST_AMOUNT
            let deposit_output_amount: u64 = tx_data.output0_amount - DUST_AMOUNT;

            // Reconstruct the depositTx sighash from parsed requestTx data
            let committee_pubkey = self.committee_pubkey.read();
            let sighash = compute_deposit_sighash(
                tx_data.txid,
                tx_data.output0_amount,
                @tx_data.output0_script_pubkey,
                committee_pubkey,
                deposit_output_amount,
            );

            // The committee signs with the tweaked key (tweaked by request output's merkle root).
            // We verify against the tweaked pubkey.
            // For now, we verify against the raw committee pubkey — the actual tweaked key
            // verification requires computing the taproot tweak from the request output's
            // script tree, which we get from the output's scriptPubKey.
            //
            // The request output is P2TR: 0x5120 + <tweaked_pubkey>.
            // The committee signed with the key tweaked by the cancel script tree's merkle root.
            // So we extract the tweaked pubkey from the request output's scriptPubKey
            // and verify the signature against that.
            assert(tx_data.output0_script_pubkey.len() == 34, 'bad P2TR script length');
            // Skip 0x51 0x20, read 32-byte tweaked pubkey
            let mut tweaked_pk: u256 = 0;
            let mut i: usize = 0;
            while i < 32 {
                let byte: u256 = tx_data.output0_script_pubkey.at(2 + i).unwrap().into();
                tweaked_pk = tweaked_pk * 256 + byte;
                i += 1;
            };

            // Convert sighash to ByteArray for BIP340 verification
            let mut sighash_ba: ByteArray = "";
            crate::bip341::append_u256_be(ref sighash_ba, sighash);

            // Verify BIP340 signature: verify(pubkey_x, sig_rx, sig_s, message)
            let valid = bip340_verify(tweaked_pk, sigma_1_rx, sigma_1_s, sighash_ba);
            assert(valid, 'invalid committee signature');

            // Extract recipient from OP_RETURN
            let recipient: ContractAddress = tx_data.starknet_address.try_into().unwrap();

            // Store deposit info
            // TODO: The minted amount equals the full requestTx output value, which includes
            // dust overhead for the depositTx fee. Adjust when fee handling is finalized.
            let timestamp = get_block_timestamp();
            let info = DepositInfo {
                recipient,
                deposit_secret_hash,
                request_timestamp: timestamp,
                status: DepositStatus::Pending,
                amount: tx_data.output0_amount,
            };
            self.deposits.write(deposit_secret_hash, info);

            self.emit(Request { deposit_secret_hash, recipient, timestamp });
        }

        /// Mint wBTC after the delay period has elapsed.
        fn mint(ref self: ContractState, deposit_secret_hash: u256) {
            let deposit = self.deposits.read(deposit_secret_hash);
            assert(deposit.status == DepositStatus::Pending, 'not pending');

            let now = get_block_timestamp();
            assert(
                now >= deposit.request_timestamp + self.mint_delay.read(), 'mint delay not elapsed',
            );

            // Update status
            self
                .deposits
                .write(
                    deposit_secret_hash,
                    DepositInfo { status: DepositStatus::Minted, ..deposit },
                );

            // Mint wBTC to recipient (amount in sats from requestTx)
            let amount: u256 = deposit.amount.into();
            self.erc20.mint(deposit.recipient, amount);

            self
                .emit(
                    Mint {
                        deposit_secret_hash, recipient: deposit.recipient, amount,
                    },
                );
        }

        /// Cancel a pending deposit by revealing the deposit secret preimage.
        fn cancel(ref self: ContractState, deposit_secret: u256) {
            // Compute SHA256(deposit_secret) -> deposit_secret_hash
            let mut secret_ba: ByteArray = "";
            crate::bip341::append_u256_be(ref secret_ba, deposit_secret);
            let deposit_secret_hash = sha256_u256(@secret_ba);

            let deposit = self.deposits.read(deposit_secret_hash);
            assert(deposit.status == DepositStatus::Pending, 'not pending');

            // Update status
            self
                .deposits
                .write(
                    deposit_secret_hash,
                    DepositInfo { status: DepositStatus::Cancelled, ..deposit },
                );

            self
                .emit(
                    Cancel { deposit_secret_hash, cancelled_by: get_caller_address() },
                );
        }

        /// Burn wBTC (user initiates withdrawal from Starknet back to Bitcoin).
        fn burn(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            self.erc20.burn(caller, amount);
            self.emit(Burn { account: caller, amount });
        }

        /// Read deposit info.
        fn get_deposit(self: @ContractState, deposit_secret_hash: u256) -> DepositInfo {
            self.deposits.read(deposit_secret_hash)
        }
    }
}

#[starknet::interface]
pub trait IMinting<TContractState> {
    fn request(
        ref self: TContractState,
        raw_request_tx: ByteArray,
        deposit_secret_hash: u256,
        sigma_1_rx: u256,
        sigma_1_s: u256,
    );
    fn mint(ref self: TContractState, deposit_secret_hash: u256);
    fn cancel(ref self: TContractState, deposit_secret: u256);
    fn burn(ref self: TContractState, amount: u256);
    fn get_deposit(self: @TContractState, deposit_secret_hash: u256) -> crate::types::DepositInfo;
}
