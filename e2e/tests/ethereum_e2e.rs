#[path = "ethereum_e2e/anvil.rs"]
mod anvil;
#[path = "ethereum_e2e/helpers.rs"]
mod helpers;

use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1::Secp256k1;

use alloy::hex;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use alloy::sol;
use alloy::sol_types::SolCall;

use bridge::actor::{Committee, Depositor};
use bridge::network::BitcoinNetwork;
use bridge::params::Params;
use bridge::scripts;
use bridge::test_support::{dummy_outpoint, test_rng_seeded};
use committee::CommitteeClient;
use depositor::DepositorClient;

use anvil::AnvilNode;

// Generate typed bindings for `MintingContract` from its forge artifact.
// Must be declared at crate root so child modules (`anvil`) can reference it.
sol!(
    #[sol(rpc)]
    MintingContract,
    "../ethereum/out/MintingContract.sol/MintingContract.json"
);

struct TestFixture {
    _network: BitcoinNetwork,
    anvil: AnvilNode,
    contract_address: Address,
    raw_request_tx_bytes: Bytes,
    deposit_secret: B256,
    deposit_secret_hash: B256,
    sig_rx: B256,
    sig_s: B256,
    tweaked_key_odd_y: bool,
    recipient: Address,
    /// Expected wBTC mint amount in satoshis — equal to the depositTx output value
    /// (request output minus DUST_AMOUNT). This is the value actually locked in
    /// committee custody and is what should be credited on mint.
    expected_mint_amount: u64,
}

impl TestFixture {
    fn contract(&self) -> MintingContract::MintingContractInstance<impl Provider + Clone> {
        MintingContract::new(self.contract_address, self.anvil.provider())
    }
}

/// Full test setup: regtest + anvil + deploy contract + prepare signed request.
async fn setup() -> TestFixture {
    // 1. Start Bitcoin regtest
    let network = BitcoinNetwork::new_regtest().unwrap();

    // 2. Build actors
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xdeadbeef);
    let eth_address: [u8; 20] = [0xab; 20];
    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
    let committee = Committee::new(&mut rng, &secp);

    let recipient = helpers::bytes_to_address(&eth_address);

    // 3. Fund depositor's request UTXO
    let request_utxo = network
        .fund_p2tr(&secp, depositor.pubkey, params.request_input_value())
        .unwrap();

    // 4. Build+sign the requestTx
    let mut dep_client = DepositorClient::new(depositor, params.clone(), eth_address);
    let request_tx = dep_client
        .create_request(committee.pubkey, request_utxo)
        .unwrap();
    network.broadcast_tx(&request_tx).unwrap();
    network.mine_blocks(1).unwrap();

    // 5. Committee presigns the depositTx → extract the 64-byte Schnorr sig.
    let committee_client = CommitteeClient::new(committee, params.clone());
    let request_txid = request_tx.compute_txid();
    let deposit_tx = committee_client
        .presign_deposit(
            request_txid,
            dep_client.depositor.pubkey,
            dep_client.depositor.deposit_secret_hash(),
            &request_tx.output[0],
        )
        .unwrap();
    let sig_bytes: [u8; 64] = deposit_tx.input[0].witness[0][..64]
        .try_into()
        .expect("σ must be 64 bytes");
    let sig_rx = B256::from_slice(&sig_bytes[0..32]);

    // 6. Serialize requestTx in non-witness format (for the contract parser).
    let raw_request_tx_bytes = dep_client.request_tx_no_witness(&request_tx);

    // 7. Compute the committee's tap-tweaked x-only pubkey (no script tree).
    //    This is the same key committee/deposit.rs uses for Address::p2tr with no merkle root.
    let untweaked: UntweakedPublicKey = committee_client.committee.pubkey;
    let (tweaked_output, _parity) = untweaked.tap_tweak(&secp, None);
    let tweaked_pk_bytes: [u8; 32] = tweaked_output.serialize();
    let deposit_tweaked_pk = B256::from_slice(&tweaked_pk_bytes);

    // 8. Compute the adjusted signature scalar for verifyTweaked.
    let request_spend_info = scripts::request_spend_info(
        &secp,
        committee_client.committee.pubkey,
        dep_client.depositor.pubkey,
        dep_client.depositor.deposit_secret_hash(),
        params.deposit_timeout,
    )
    .unwrap();
    let (sig_s_bytes, tweaked_key_odd_y) = depositor::adjusted_sig::compute_adjusted_sig(
        sig_bytes[0..32].try_into().unwrap(),
        sig_bytes[32..64].try_into().unwrap(),
        &deposit_tx,
        &request_tx.output[0],
        &request_spend_info,
    )
    .unwrap();
    let sig_s = B256::from_slice(&sig_s_bytes);

    // 9. Start anvil and deploy the minting contract.
    let committee_internal_pk = B256::from_slice(&committee_client.committee.pubkey.serialize());
    let anvil = AnvilNode::start().await;
    let contract_address = anvil
        .deploy_minting_contract(committee_internal_pk, deposit_tweaked_pk, params.deposit_size.to_sat(), 86400)
        .await;

    let deposit_secret = B256::from_slice(&dep_client.depositor.deposit_secret);
    let deposit_secret_hash = B256::from_slice(&dep_client.depositor.deposit_secret_hash());

    TestFixture {
        _network: network,
        anvil,
        contract_address,
        raw_request_tx_bytes: raw_request_tx_bytes.into(),
        deposit_secret,
        deposit_secret_hash,
        sig_rx,
        sig_s,
        tweaked_key_odd_y,
        recipient,
        expected_mint_amount: deposit_tx.output[0].value.to_sat(),
    }
}

// === Tests ===

#[tokio::test]
async fn test_happy_path() {
    let f = setup().await;
    let c = f.contract();

    c.request(
        f.raw_request_tx_bytes.clone(),
        f.deposit_secret_hash,
        f.sig_rx,
        f.sig_s,
        f.tweaked_key_odd_y,
    )
    .send()
    .await
    .expect("request failed")
    .watch()
    .await
    .expect("request not mined");

    // Advance past the mint delay.
    f.anvil.increase_time(86401).await;

    c.mint(f.deposit_secret_hash)
        .send()
        .await
        .expect("mint failed")
        .watch()
        .await
        .expect("mint not mined");

    let balance: U256 = c.balanceOf(f.recipient).call().await.unwrap();
    assert_eq!(balance, U256::from(f.expected_mint_amount));
}

#[tokio::test]
async fn test_cancel_blocks_mint() {
    let f = setup().await;
    let c = f.contract();

    c.request(
        f.raw_request_tx_bytes.clone(),
        f.deposit_secret_hash,
        f.sig_rx,
        f.sig_s,
        f.tweaked_key_odd_y,
    )
    .send()
    .await
    .expect("request failed")
    .watch()
    .await
    .unwrap();

    c.cancel(f.deposit_secret)
        .send()
        .await
        .expect("cancel failed")
        .watch()
        .await
        .unwrap();

    // Mint should revert ("not pending") now that the deposit has been cancelled.
    let err = c.mint(f.deposit_secret_hash).send().await.err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("not pending"),
        "expected 'not pending' revert, got: {err_str}"
    );
}

#[tokio::test]
async fn test_early_mint_rejected() {
    let f = setup().await;
    let c = f.contract();

    c.request(
        f.raw_request_tx_bytes.clone(),
        f.deposit_secret_hash,
        f.sig_rx,
        f.sig_s,
        f.tweaked_key_odd_y,
    )
    .send()
    .await
    .expect("request failed")
    .watch()
    .await
    .unwrap();

    // No time advance → mint must revert with "mint delay not elapsed".
    let err = c.mint(f.deposit_secret_hash).send().await.err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("mint delay not elapsed"),
        "expected 'mint delay not elapsed' revert, got: {err_str}"
    );
}

#[tokio::test]
async fn test_invalid_signature() {
    let f = setup().await;
    let c = f.contract();

    let err = c
        .request(
            f.raw_request_tx_bytes.clone(),
            f.deposit_secret_hash,
            B256::ZERO,
            B256::ZERO,
            f.tweaked_key_odd_y,
        )
        .send()
        .await
        .err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("invalid committee signature"),
        "expected 'invalid committee signature' revert, got: {err_str}"
    );
}

#[tokio::test]
async fn test_duplicate_request() {
    let f = setup().await;
    let c = f.contract();

    c.request(
        f.raw_request_tx_bytes.clone(),
        f.deposit_secret_hash,
        f.sig_rx,
        f.sig_s,
        f.tweaked_key_odd_y,
    )
    .send()
    .await
    .expect("first request failed")
    .watch()
    .await
    .unwrap();

    let err = c
        .request(
            f.raw_request_tx_bytes.clone(),
            f.deposit_secret_hash,
            f.sig_rx,
            f.sig_s,
            f.tweaked_key_odd_y,
        )
        .send()
        .await
        .err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("deposit already requested"),
        "expected 'deposit already requested' revert, got: {err_str}"
    );
}

#[tokio::test]
async fn test_burn_after_mint() {
    let f = setup().await;
    let c = f.contract();

    c.request(
        f.raw_request_tx_bytes.clone(),
        f.deposit_secret_hash,
        f.sig_rx,
        f.sig_s,
        f.tweaked_key_odd_y,
    )
    .send()
    .await
    .expect("request failed")
    .watch()
    .await
    .unwrap();

    f.anvil.increase_time(86401).await;

    c.mint(f.deposit_secret_hash)
        .send()
        .await
        .expect("mint failed")
        .watch()
        .await
        .unwrap();

    let balance: U256 = c.balanceOf(f.recipient).call().await.unwrap();
    assert_eq!(balance, U256::from(f.expected_mint_amount));

    // Impersonate the recipient so it can burn its own tokens.
    let provider = f.anvil.provider();
    let _: () = provider
        .client()
        .request("anvil_impersonateAccount", (f.recipient,))
        .await
        .expect("impersonate failed");
    // Fund the recipient with some ETH for gas.
    let _: () = provider
        .client()
        .request(
            "anvil_setBalance",
            (f.recipient, U256::from(10u128.pow(18))),
        )
        .await
        .expect("setBalance failed");

    // Build burn() calldata and send via eth_sendTransaction so anvil signs with the
    // impersonated account (alloy's local wallet filler can't sign for it).
    let burn_calldata = MintingContract::burnCall {
        amount: U256::from(f.expected_mint_amount),
    }
    .abi_encode();
    let tx = serde_json::json!({
        "from": f.recipient,
        "to": f.contract_address,
        "data": format!("0x{}", hex::encode(&burn_calldata)),
    });
    let tx_hash: B256 = provider
        .client()
        .request("eth_sendTransaction", (tx,))
        .await
        .expect("burn tx failed");
    // Wait for the tx to be mined.
    loop {
        if provider
            .get_transaction_receipt(tx_hash)
            .await
            .unwrap()
            .is_some()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let balance_after: U256 = c.balanceOf(f.recipient).call().await.unwrap();
    assert_eq!(balance_after, U256::ZERO);
}

#[tokio::test]
async fn test_cancel_after_mint() {
    let f = setup().await;
    let c = f.contract();

    c.request(
        f.raw_request_tx_bytes.clone(),
        f.deposit_secret_hash,
        f.sig_rx,
        f.sig_s,
        f.tweaked_key_odd_y,
    )
    .send()
    .await
    .expect("request failed")
    .watch()
    .await
    .unwrap();

    f.anvil.increase_time(86401).await;

    c.mint(f.deposit_secret_hash)
        .send()
        .await
        .expect("mint failed")
        .watch()
        .await
        .unwrap();

    let err = c.cancel(f.deposit_secret).send().await.err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("not pending"),
        "expected 'not pending' revert, got: {err_str}"
    );
}
