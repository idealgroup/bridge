#[path = "starknet_e2e/devnet.rs"]
mod devnet;
#[path = "starknet_e2e/helpers.rs"]
mod helpers;

use bitcoin::secp256k1::Secp256k1;

use starknet::accounts::Account;
use starknet::core::types::{
    BlockId, BlockTag, Call, ExecutionResult, Felt, FunctionCall, TransactionReceipt,
};
use starknet::macros::selector;
use starknet::providers::Provider;

use bridge::actor::{Committee, Depositor};
use bridge::network::BitcoinNetwork;
use bridge::params::Params;
use bridge::test_support::{dummy_outpoint, test_rng_seeded};
use committee::CommitteeClient;
use depositor::DepositorClient;

use devnet::{wait_for_tx, DevnetNode, StarknetAccount};

struct TestFixture {
    _network: BitcoinNetwork,
    devnet: DevnetNode,
    contract_address: Felt,
    raw_request_tx_bytes: Vec<u8>,
    deposit_secret: [u8; 32],
    deposit_secret_hash: [u8; 32],
    sigma_1: [u8; 64],
    request_output0_amount: u64,
    account_address: Felt,
}

impl TestFixture {
    /// Build calldata for the `request()` entrypoint.
    fn request_calldata(&self) -> Vec<Felt> {
        let mut calldata = helpers::bytes_to_bytearray_calldata(&self.raw_request_tx_bytes);
        let (dsh_low, dsh_high) = helpers::bytes32_to_u256_felts(&self.deposit_secret_hash);
        calldata.push(dsh_low);
        calldata.push(dsh_high);
        let (rx_low, rx_high, s_low, s_high) = helpers::schnorr_sig_to_felts(&self.sigma_1);
        calldata.push(rx_low);
        calldata.push(rx_high);
        calldata.push(s_low);
        calldata.push(s_high);
        calldata
    }

    /// Build calldata for the `mint()` entrypoint.
    fn mint_calldata(&self) -> Vec<Felt> {
        let (dsh_low, dsh_high) = helpers::bytes32_to_u256_felts(&self.deposit_secret_hash);
        vec![dsh_low, dsh_high]
    }

    /// Build calldata for the `cancel()` entrypoint.
    fn cancel_calldata(&self) -> Vec<Felt> {
        let (sec_low, sec_high) = helpers::bytes32_to_u256_felts(&self.deposit_secret);
        vec![sec_low, sec_high]
    }

    /// Build calldata for the `burn()` entrypoint.
    fn burn_calldata(&self, amount: u64) -> Vec<Felt> {
        let (low, high) = helpers::u64_to_u256_felts(amount);
        vec![low, high]
    }

    /// Get a fresh account handle for making contract calls.
    async fn account(&self) -> StarknetAccount {
        self.devnet.predeployed_account().await
    }

    /// Query wBTC balance of the recipient account.
    async fn balance_of_recipient(&self) -> u64 {
        let result: Vec<Felt> = Provider::call(
            self.devnet.provider.as_ref(),
            FunctionCall {
                contract_address: self.contract_address,
                entry_point_selector: selector!("balance_of"),
                calldata: vec![self.account_address],
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .expect("balance_of call failed");

        // u256 return: [low, high]. Amount fits in u64.
        let bytes = result[0].to_bytes_be();
        u64::from_be_bytes(bytes[24..32].try_into().unwrap())
    }

    /// Execute a contract call and assert it succeeds.
    async fn execute_ok(&self, selector: Felt, calldata: Vec<Felt>) {
        let account: StarknetAccount = self.account().await;
        let call = Call {
            to: self.contract_address,
            selector,
            calldata,
        };
        let result = account.execute_v3(vec![call]).send().await.expect("execute failed");
        wait_for_tx(&self.devnet.provider, result.transaction_hash).await;

        // Check receipt for execution success
        let receipt = Provider::get_transaction_receipt(
            self.devnet.provider.as_ref(),
            result.transaction_hash,
        )
        .await
        .unwrap();
        let exec_result = execution_result_of(&receipt.receipt);
        assert!(
            matches!(exec_result, ExecutionResult::Succeeded),
            "expected success, got: {exec_result:?}"
        );
    }

    /// Execute a contract call and assert it reverts with expected message.
    async fn execute_expect_revert(&self, selector: Felt, calldata: Vec<Felt>, expected_msg: &str) {
        let account: StarknetAccount = self.account().await;
        let call = Call {
            to: self.contract_address,
            selector,
            calldata,
        };
        match account.execute_v3(vec![call]).send().await {
            Err(e) => {
                let err_str = format!("{e:?}");
                assert!(
                    err_str.contains(expected_msg),
                    "expected '{expected_msg}' in error, got: {err_str}"
                );
            }
            Ok(result) => {
                wait_for_tx(&self.devnet.provider, result.transaction_hash).await;
                let receipt = Provider::get_transaction_receipt(
                    self.devnet.provider.as_ref(),
                    result.transaction_hash,
                )
                .await
                .unwrap();
                let exec_result = execution_result_of(&receipt.receipt);
                match exec_result {
                    ExecutionResult::Reverted { reason } => {
                        assert!(
                            reason.contains(expected_msg),
                            "expected '{expected_msg}' in revert reason, got: {reason}"
                        );
                    }
                    ExecutionResult::Succeeded => {
                        panic!("expected revert with '{expected_msg}', but transaction succeeded");
                    }
                }
            }
        }
    }
}

fn execution_result_of(receipt: &TransactionReceipt) -> &ExecutionResult {
    match receipt {
        TransactionReceipt::Invoke(r) => &r.execution_result,
        TransactionReceipt::Declare(r) => &r.execution_result,
        TransactionReceipt::DeployAccount(r) => &r.execution_result,
        TransactionReceipt::Deploy(r) => &r.execution_result,
        TransactionReceipt::L1Handler(r) => &r.execution_result,
    }
}

/// Full test setup: regtest + devnet + deploy contract.
async fn setup() -> TestFixture {
    // 1. Start starknet-devnet and get predeployed account address
    let devnet: DevnetNode = DevnetNode::start().await;
    let account: StarknetAccount = devnet.predeployed_account().await;
    let account_address = account.address();
    let starknet_addr_bytes: [u8; 32] = account_address.to_bytes_be();

    // 2. Start Bitcoin regtest
    let network = BitcoinNetwork::new_regtest().unwrap();

    // 3. Create actors
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xdeadbeef);
    let mut depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
    depositor.starknet_address = starknet_addr_bytes;
    let committee = Committee::new(&mut rng, &secp);

    // 4. Fund depositor
    let request_utxo = network
        .fund_p2tr(&secp, depositor.pubkey, params.request_input_value())
        .unwrap();

    // 5. Build+sign requestTx
    let mut dep_client = DepositorClient::new(depositor, params.clone());
    let request_tx = dep_client
        .create_request(committee.pubkey, request_utxo)
        .unwrap();
    network.broadcast_tx(&request_tx).unwrap();
    network.mine_blocks(1).unwrap();

    // 6. Committee presigns deposit -> extract σ₁ (64-byte BIP340 Schnorr sig)
    let committee_client = CommitteeClient::new(committee, params);
    let request_txid = request_tx.compute_txid();
    let deposit_tx = committee_client
        .presign_deposit(request_txid, &dep_client.depositor, &request_tx.output[0])
        .unwrap();
    // TapSighashType::Default -> witness[0] is exactly 64 bytes (no sighash flag byte)
    let sigma_1: [u8; 64] = deposit_tx.input[0].witness[0][..64]
        .try_into()
        .expect("σ₁ must be 64 bytes");

    // 7. Serialize requestTx in non-witness format (for Cairo txid computation)
    let raw_request_tx_bytes = helpers::serialize_tx_no_witness(&request_tx);

    // 8. Build Cairo artifacts + declare+deploy on devnet
    DevnetNode::build_contract_artifacts();
    let pk_bytes = committee_client.committee.pubkey.serialize();
    let (pk_low, pk_high) = helpers::bytes32_to_u256_felts(&pk_bytes);
    let contract_address = devnet
        .declare_and_deploy(pk_low, pk_high, 86400)
        .await;

    TestFixture {
        _network: network,
        devnet,
        contract_address,
        raw_request_tx_bytes,
        deposit_secret: dep_client.depositor.deposit_secret,
        deposit_secret_hash: dep_client.depositor.deposit_secret_hash(),
        sigma_1,
        request_output0_amount: request_tx.output[0].value.to_sat(),
        account_address,
    }
}

// === Tests ===

#[tokio::test]
async fn test_happy_path() {
    let f = setup().await;

    // Submit deposit request with real BIP340 signature
    f.execute_ok(selector!("request"), f.request_calldata()).await;

    // Advance time past mint delay (86400s + 1)
    f.devnet.increase_time(86401).await;

    // Mint
    f.execute_ok(selector!("mint"), f.mint_calldata()).await;

    // Verify recipient received wBTC equal to request output 0 amount
    let balance = f.balance_of_recipient().await;
    assert_eq!(balance, f.request_output0_amount);
}

#[tokio::test]
async fn test_cancel_blocks_mint() {
    let f = setup().await;

    // Submit request
    f.execute_ok(selector!("request"), f.request_calldata()).await;

    // Cancel with deposit secret
    f.execute_ok(selector!("cancel"), f.cancel_calldata()).await;

    // Mint should fail — status is Cancelled, not Pending
    f.execute_expect_revert(selector!("mint"), f.mint_calldata(), "not pending")
        .await;
}

#[tokio::test]
async fn test_early_mint_rejected() {
    let f = setup().await;

    // Submit request
    f.execute_ok(selector!("request"), f.request_calldata()).await;

    // Try to mint immediately (no time increase)
    f.execute_expect_revert(
        selector!("mint"),
        f.mint_calldata(),
        "mint delay not elapsed",
    )
    .await;
}

#[tokio::test]
async fn test_invalid_signature() {
    let f = setup().await;

    // Build request calldata with zeroed signature
    let mut calldata = helpers::bytes_to_bytearray_calldata(&f.raw_request_tx_bytes);
    let (dsh_low, dsh_high) = helpers::bytes32_to_u256_felts(&f.deposit_secret_hash);
    calldata.push(dsh_low);
    calldata.push(dsh_high);
    // Zeroed rx and s
    calldata.push(Felt::ZERO); // rx_low
    calldata.push(Felt::ZERO); // rx_high
    calldata.push(Felt::ZERO); // s_low
    calldata.push(Felt::ZERO); // s_high

    f.execute_expect_revert(selector!("request"), calldata, "invalid committee signature")
        .await;
}

#[tokio::test]
async fn test_duplicate_request() {
    let f = setup().await;

    // First request succeeds
    f.execute_ok(selector!("request"), f.request_calldata()).await;

    // Second identical request should fail
    f.execute_expect_revert(
        selector!("request"),
        f.request_calldata(),
        "deposit already requested",
    )
    .await;
}

#[tokio::test]
async fn test_burn_after_mint() {
    let f = setup().await;

    // Happy path: request → wait → mint
    f.execute_ok(selector!("request"), f.request_calldata()).await;
    f.devnet.increase_time(86401).await;
    f.execute_ok(selector!("mint"), f.mint_calldata()).await;

    // Verify balance before burn
    let balance = f.balance_of_recipient().await;
    assert_eq!(balance, f.request_output0_amount);

    // Burn all
    f.execute_ok(selector!("burn"), f.burn_calldata(f.request_output0_amount))
        .await;

    // Balance should be 0
    let balance_after = f.balance_of_recipient().await;
    assert_eq!(balance_after, 0);
}

#[tokio::test]
async fn test_cancel_after_mint() {
    let f = setup().await;

    // Happy path: request → wait → mint
    f.execute_ok(selector!("request"), f.request_calldata()).await;
    f.devnet.increase_time(86401).await;
    f.execute_ok(selector!("mint"), f.mint_calldata()).await;

    // Cancel should fail — status is Minted, not Pending
    f.execute_expect_revert(selector!("cancel"), f.cancel_calldata(), "not pending")
        .await;
}
