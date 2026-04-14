use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::TxOut;

use bridge::actor::{Committee, Depositor};
use bridge::params::Params;
use bridge::scripts;
use bridge::test_support::{test_rng_seeded, dummy_outpoint, BITCOIN_NETWORK};

use depositor::DepositorClient;

/// Depositor funds a request UTXO, creates a requestTx via the client, broadcasts it.
#[test]
fn test_depositor_creates_request() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(77);

    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
    let committee = Committee::new(&mut rng, &secp);

    let request_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();

    let mut client = DepositorClient::new(depositor, params.clone());

    let request_tx = client
        .create_request(committee.pubkey, request_utxo)
        .unwrap();

    assert_eq!(request_tx.output.len(), 2);
    assert_eq!(request_tx.output[0].value, params.request_input_value());
    assert!(request_tx.output[1].script_pubkey.is_op_return());

    BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
}

/// After deposit_timeout+1 blocks, the depositor can cancel via the escape hatch.
/// The cancel witness must contain the deposit_secret (witness[1]).
#[test]
fn test_depositor_cancel_after_timeout() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(77);

    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
    let committee = Committee::new(&mut rng, &secp);

    let request_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();

    let mut client = DepositorClient::new(depositor, params.clone());

    let request_tx = client
        .create_request(committee.pubkey, request_utxo)
        .unwrap();
    BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();

    // Mine enough blocks for CSV to be satisfied
    BITCOIN_NETWORK
        .mine_blocks(params.deposit_timeout.to_consensus_u32() as u64 + 1)
        .unwrap();

    let request_txid = request_tx.compute_txid();
    let cancel_tx = client
        .create_cancel(committee.pubkey, request_txid, &request_tx.output[0])
        .unwrap();

    // deposit_secret is witness[1] in the cancel script-path spend
    assert_eq!(cancel_tx.input[0].witness[1].len(), 32);

    BITCOIN_NETWORK.broadcast_tx(&cancel_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
}

/// Cancel with insufficient nSequence must be rejected (CSV not satisfied).
/// Uses low-level functions to set nSequence below deposit_timeout, which
/// reliably triggers OP_CSV rejection regardless of shared regtest chain state.
#[test]
fn test_depositor_cancel_before_timeout_rejected() {
    use bitcoin::blockdata::transaction::Sequence;
    use depositor::{cancel, request};

    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(77);

    let mut depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
    let committee = Committee::new(&mut rng, &secp);

    depositor.request_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();

    let mut request_tx =
        request::build_request_tx(&secp, &depositor, committee.pubkey, &params).unwrap();
    let depositor_prevout = TxOut {
        value: params.request_input_value(),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr(&secp, depositor.pubkey, None),
    };
    request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout])
        .unwrap();
    BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();

    let request_spend_info = scripts::request_spend_info(
        &secp,
        committee.pubkey,
        depositor.pubkey,
        depositor.deposit_secret_hash(),
        params.deposit_timeout,
    )
    .unwrap();

    let request_txid = request_tx.compute_txid();
    let mut cancel_tx =
        cancel::build_cancel_tx(&secp, &depositor, request_txid, &params).unwrap();

    // Set nSequence too low — OP_CSV(deposit_timeout=5) will reject nSequence=1
    cancel_tx.input[0].sequence = Sequence::from_height(1);

    let prevouts = [request_tx.output[0].clone()];
    cancel::sign_cancel_tx(
        &secp,
        &mut cancel_tx,
        &depositor.keypair,
        &depositor.deposit_secret,
        &request_spend_info,
        depositor.pubkey,
        depositor.deposit_secret_hash(),
        params.deposit_timeout,
        &prevouts,
    )
    .unwrap();

    assert!(
        BITCOIN_NETWORK.broadcast_tx(&cancel_tx).is_err(),
        "cancel with insufficient nSequence should be rejected by OP_CSV"
    );
}

