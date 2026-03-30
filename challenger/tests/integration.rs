use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, OutPoint, Txid};

use bridge::actor::Operator;
use bridge::engine::MockEngine;
use bridge::params::Params;
use bridge::regtest::RegtestNode;
use bridge::test_support::test_rng_seeded;

use challenger::ChallengerClient;
use operator::OperatorClient;

/// Start a fresh isolated regtest node for a single test.
fn fresh_node() -> RegtestNode {
    let node = RegtestNode::start().expect("start regtest node");
    node.mine_blocks(101).expect("mine for coinbase maturity");
    node
}

/// Helper: create operator, build kickoff for given slot/proof, broadcast everything.
/// Returns the kickoff tx (last in the returned vec).
fn setup_and_broadcast_kickoff(
    node: &RegtestNode,
    params: &Params,
    slot: usize,
    disprove_hash: [u8; 32],
    proof_msg: &[u8; lamport::MSG_LEN],
) {
    let secp = Secp256k1::new();
    let mut rng = test_rng_seeded(99);

    let mut operator = Operator::new(
        &mut rng,
        &secp,
        OutPoint::new(Txid::all_zeros(), 0),
        params.deposit_count,
    );

    let addr = Address::p2tr(&secp, operator.pubkey, None, Network::Regtest);
    operator.init_utxo = node
        .fund_address(&addr, params.fanout_init_value())
        .expect("fund operator");

    let mut client = OperatorClient::new(operator, params.clone());
    let txs = client
        .create_kickoff(slot, disprove_hash, proof_msg)
        .unwrap();

    for tx in &txs {
        node.send_transaction(tx).unwrap();
    }
    node.mine_blocks(1).unwrap();
}

#[test]
fn test_challenger_detects_and_disproves_invalid_proof() {
    let params = Params::test_defaults();
    let node = fresh_node();

    // Create kickoff with an invalid proof (proof[0] = 0xFF triggers MockEngine disprove)
    let slot = 0;
    let mut proof_msg = [0u8; lamport::MSG_LEN];
    proof_msg[0] = 0xFF;

    // The disprove_secret for MockEngine is proof[0..20]
    let disprove_secret = {
        let mut s = [0u8; 20];
        s.copy_from_slice(&proof_msg[0..20]);
        s
    };
    let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();

    setup_and_broadcast_kickoff(&node, &params, slot, disprove_hash, &proof_msg);

    // Challenger side: scan the tip block for kickoffs
    use bitcoincore_rpc::RpcApi;
    let tip = node.client.get_block_count().unwrap();
    let hash = node.client.get_block_hash(tip).unwrap();
    let block = node.client.get_block(&hash).unwrap();

    let challenger = ChallengerClient::new(MockEngine, params);
    let candidates = challenger.scan_block_for_kickoffs(&block);
    assert_eq!(candidates.len(), 1);

    let result = challenger.challenge_kickoff(&candidates[0]).unwrap();
    assert!(result.is_some(), "challenger should detect invalid proof");

    let disprove_tx = result.unwrap();
    node.send_transaction(&disprove_tx).unwrap();
    node.mine_blocks(1).unwrap();
}

#[test]
fn test_challenger_ignores_valid_proof() {
    let params = Params::test_defaults();
    let node = fresh_node();

    // Valid proof: proof[0] = 0x00
    let slot = 0;
    let proof_msg = [0u8; lamport::MSG_LEN];

    // For valid proof, MockEngine returns None, so we can use any disprove_hash
    let disprove_hash = [0xaa; 32];

    setup_and_broadcast_kickoff(&node, &params, slot, disprove_hash, &proof_msg);

    // Challenger side: scan the tip block
    use bitcoincore_rpc::RpcApi;
    let tip = node.client.get_block_count().unwrap();
    let hash = node.client.get_block_hash(tip).unwrap();
    let block = node.client.get_block(&hash).unwrap();

    let challenger = ChallengerClient::new(MockEngine, params);
    let candidates = challenger.scan_block_for_kickoffs(&block);
    assert_eq!(candidates.len(), 1);

    let result = challenger.challenge_kickoff(&candidates[0]).unwrap();
    assert!(result.is_none(), "challenger should ignore valid proof");
}

#[test]
fn test_challenger_scan_block_finds_kickoff() {
    let params = Params::test_defaults();
    let node = fresh_node();

    let slot = 0;
    let mut proof_msg = [0u8; lamport::MSG_LEN];
    proof_msg[0] = 0xFF;

    let disprove_secret = {
        let mut s = [0u8; 20];
        s.copy_from_slice(&proof_msg[0..20]);
        s
    };
    let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();

    setup_and_broadcast_kickoff(&node, &params, slot, disprove_hash, &proof_msg);

    // Challenger side: scan the tip block
    use bitcoincore_rpc::RpcApi;
    let tip = node.client.get_block_count().unwrap();
    let hash = node.client.get_block_hash(tip).unwrap();
    let block = node.client.get_block(&hash).unwrap();

    let challenger = ChallengerClient::new(MockEngine, params);
    let candidates = challenger.scan_block_for_kickoffs(&block);
    assert_eq!(candidates.len(), 1, "scan should find exactly one kickoff");

    let result = challenger.challenge_kickoff(&candidates[0]).unwrap();
    assert!(result.is_some(), "should detect invalid proof from scanned tx");

    let disprove_tx = result.unwrap();
    node.send_transaction(&disprove_tx).unwrap();
    node.mine_blocks(1).unwrap();
}
