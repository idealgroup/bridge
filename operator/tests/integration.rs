use bitcoin::secp256k1::Secp256k1;

use bridge::actor::Operator;
use bridge::network::BITCOIN_NETWORK;
use bridge::params::Params;
use bridge::test_support::{test_rng_seeded, dummy_outpoint};

use operator::OperatorClient;

/// Operator builds fanout tree, broadcasts, creates kickoff, confirms on-chain.
#[test]
fn test_operator_creates_fanout_and_kickoff() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(99);

    let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
    operator.init_utxo =
        BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    let mut client = OperatorClient::new(operator, params.clone());

    // Create kickoff for slot 0 — lazily builds fanout tree, returns fanout path + kickoff
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let proof_msg = [0xbb; lamport::MSG_LEN];

    let txs = client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();

    for tx in &txs {
        BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
    }
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

    // Build and sign fanout tree with correct keys (no broadcast)
    client.create_fanout_tree().unwrap();

    // Swap Lamport keys: slot 0 now has slot 1's key
    client.operator.lamport_keys.swap(0, 1);

    // Create kickoff for slot 0 — uses wrong Lamport key (slot 1's)
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let proof_msg = [0xbb; lamport::MSG_LEN];

    let txs = client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();

    // Broadcast fanout path (all but last)
    for tx in &txs[..txs.len() - 1] {
        BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
    }
    BITCOIN_NETWORK.mine_blocks(1).unwrap();

    // Broadcast kickoff should fail: wrong Lamport key doesn't match fanout leaf commitment
    assert!(
        BITCOIN_NETWORK.broadcast_tx(txs.last().unwrap()).is_err(),
        "kickoff with wrong Lamport key should be rejected"
    );
}
