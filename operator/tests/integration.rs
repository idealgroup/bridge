use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::TxOut;
use bitcoin::ScriptBuf;

use bridge::actor::{Committee, Depositor, Operator};
use bridge::network::BITCOIN_NETWORK;
use bridge::params::Params;
use bridge::scripts;
use bridge::test_support::{test_rng_seeded, dummy_outpoint};

use operator::OperatorClient;

/// Operator builds fanout tree, broadcasts, creates kickoff, confirms on-chain.
/// No depositor or committee state shared.
#[test]
fn test_operator_creates_fanout_and_kickoff() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(99);

    let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
    operator.init_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    let mut client = OperatorClient::new(operator, params.clone());

    // Build, sign, broadcast fanout tree
    client.create_fanout_tree(&BITCOIN_NETWORK).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
    assert!(client.operator.fanout_tree.is_some());

    // Create kickoff for slot 0
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let proof_msg = [0xbb; lamport::MSG_LEN];

    let kickoff_tx = client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();

    BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
}

/// Full happy path: depositor creates request, committee presigns deposit + withdraw,
/// operator builds fanout + kickoff, waits timeout, completes withdraw.
/// Each actor only communicates via transactions and explicit presigned-tx handoff.
#[test]
fn test_operator_completes_withdraw() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(99);

    // === Depositor setup (independent actor) ===
    let mut depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
    depositor.request_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();

    // === Committee setup (independent actor) ===
    let committee = Committee::new(&mut rng, &secp);

    // === Operator client setup (independent actor) ===
    let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
    operator.init_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();
    let mut client = OperatorClient::new(operator, params.clone());

    // --- Depositor creates request (on-chain) ---
    let request_tx = depositor
        .create_request(&secp, committee.pubkey, &params)
        .unwrap();
    BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
    let request_txid = request_tx.compute_txid();

    // --- Committee presigns deposit (on-chain) ---
    let deposit_tx = committee
        .presign_deposit(
            &secp,
            request_txid,
            &depositor,
            &request_tx.output[0],
            &params,
        )
        .unwrap();
    BITCOIN_NETWORK.broadcast_tx(&deposit_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
    let deposit_txid = deposit_tx.compute_txid();

    // --- Operator creates fanout tree (on-chain) ---
    client.create_fanout_tree(&BITCOIN_NETWORK).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();

    // --- Deterministic kickoff txid (operator computes, shares with committee) ---
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let kickoff_txid = client.kickoff_txid(slot, disprove_hash).unwrap();

    // --- Construct withdraw prevouts ---
    // deposit prevout: observable on-chain
    // connector prevout: deterministic from operator pubkey + disprove_hash
    let connector_info =
        scripts::connector_spend_info(&secp, client.operator.pubkey, disprove_hash).unwrap();
    let connector_output = TxOut {
        value: params.dust_amount,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
    };
    let withdraw_prevouts = vec![deposit_tx.output[0].clone(), connector_output];

    // --- Committee presigns withdraw (message passing: knows operator pubkey + kickoff_txid) ---
    let presigned_withdraw = committee
        .presign_withdraw(
            &secp,
            deposit_txid,
            kickoff_txid,
            &client.operator,
            &withdraw_prevouts,
            &params,
        )
        .unwrap();

    // --- Operator receives presigned withdraw (explicit message passing) ---
    client
        .receive_presigned_withdraw(presigned_withdraw)
        .unwrap();

    // --- Operator creates and broadcasts kickoff ---
    let proof_msg = [0xbb; lamport::MSG_LEN];
    let kickoff_tx = client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();
    assert_eq!(kickoff_tx.compute_txid(), kickoff_txid);
    BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();

    // --- Wait for timeout ---
    BITCOIN_NETWORK.mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64).unwrap();

    // --- Operator completes withdraw (signs input 1 + broadcasts) ---
    let _withdraw_tx = client
        .complete_withdraw(kickoff_txid, disprove_hash, &withdraw_prevouts, &BITCOIN_NETWORK)
        .unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();
}

/// Operator signs kickoff with wrong slot's Lamport key, bitcoind rejects it.
#[test]
fn test_operator_kickoff_rejected_with_wrong_lamport() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(99);

    let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
    operator.init_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    let mut client = OperatorClient::new(operator, params.clone());

    // Build and broadcast fanout tree with correct keys
    client.create_fanout_tree(&BITCOIN_NETWORK).unwrap();
    BITCOIN_NETWORK.mine_blocks(1).unwrap();

    // Swap Lamport keys: slot 0 now has slot 1's key
    client.operator.lamport_keys.swap(0, 1);

    // Create kickoff for slot 0 — uses wrong Lamport key (slot 1's)
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let proof_msg = [0xbb; lamport::MSG_LEN];

    let kickoff_tx = client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();

    // Broadcast should fail: wrong Lamport key doesn't match fanout leaf commitment
    assert!(
        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).is_err(),
        "kickoff with wrong Lamport key should be rejected"
    );
}
