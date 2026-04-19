use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{OutPoint, ScriptBuf, Txid, Witness};

use bridge::actor::{Committee, Depositor, Operator};
use bridge::engine::MockEngine;
use bridge::network::BitcoinNetwork;
use bridge::params::Params;
use bridge::scripts;
use bridge::test_support::{test_rng_seeded, dummy_outpoint};

use challenger::ChallengerClient;
use committee::CommitteeClient;
use depositor::DepositorClient;
use operator::OperatorClient;

/// Start a fresh isolated regtest node for a single test.
fn fresh_network() -> BitcoinNetwork {
    BitcoinNetwork::new_regtest().expect("start regtest node")
}

/// Full deposit -> withdraw cycle. Each actor uses only its own client API.
///
/// DepositorClient creates request, CommitteeClient presigns deposit + withdraw,
/// OperatorClient builds fanout + kickoff, waits timeout, completes withdraw.
#[test]
fn test_happy_path_deposit_and_withdraw() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xe2e);
    let network = fresh_network();

    // === Create actors (each independent) ===
    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint(), [0xaa; 20]);
    let committee = Committee::new(&mut rng, &secp);
    let operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);

    // === Fund actors ===
    let request_utxo =
        network.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
    let operator_init_utxo =
        network.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    // === Wrap in client APIs ===
    let mut dep_client = DepositorClient::new(depositor, params.clone());
    let committee_client = CommitteeClient::new(committee, params.clone());
    let mut op_operator = operator;
    op_operator.init_utxo = operator_init_utxo;
    let mut op_client = OperatorClient::new(op_operator, params.clone());

    // === 1. Depositor creates request ===
    let request_tx = dep_client
        .create_request(committee_client.committee.pubkey, request_utxo)
        .unwrap();
    network.broadcast_tx(&request_tx).unwrap();
    network.mine_blocks(1).unwrap();
    let request_txid = request_tx.compute_txid();

    // === 2. Committee presigns deposit ===
    let deposit_tx = committee_client
        .presign_deposit(
            request_txid,
            dep_client.depositor.pubkey,
            dep_client.depositor.deposit_secret_hash(),
            &request_tx.output[0],
        )
        .unwrap();
    network.broadcast_tx(&deposit_tx).unwrap();
    network.mine_blocks(1).unwrap();
    let deposit_txid = deposit_tx.compute_txid();

    // === 3. Compute deterministic kickoff txid (lazily builds fanout tree) ===
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let kickoff_txid = op_client.kickoff_txid(slot, disprove_hash).unwrap();

    // === 6. Build withdraw prevouts ===
    let connector_info =
        scripts::connector_spend_info(&secp, op_client.operator.pubkey, disprove_hash).unwrap();
    let connector_output = TxOut {
        value: params.dust_amount,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
    };
    let withdraw_prevouts = vec![deposit_tx.output[0].clone(), connector_output];

    // === 7. Committee presigns withdraw ===
    let presigned_withdraw = committee_client
        .presign_withdraw(
            deposit_txid,
            kickoff_txid,
            op_client.operator.pubkey,
            &withdraw_prevouts,
        )
        .unwrap();

    // Hand presigned withdraw to operator
    op_client
        .receive_presigned_withdraw(presigned_withdraw)
        .unwrap();

    // === 8. Operator creates and broadcasts kickoff (with fanout path) ===
    let proof_msg = [0xbb; lamport::MSG_LEN];
    let txs = op_client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();
    let kickoff_tx = txs.last().unwrap();
    assert_eq!(kickoff_tx.compute_txid(), kickoff_txid);
    for tx in &txs {
        network.broadcast_tx(tx).unwrap();
    }
    network.mine_blocks(1).unwrap();

    // === 9. Mine kickoff_timeout blocks ===
    network
        .mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64)
        .unwrap();

    // === 10. Operator completes withdraw ===
    let withdraw_tx = op_client
        .complete_withdraw(kickoff_txid, disprove_hash, &withdraw_prevouts, &network)
        .unwrap();
    network.mine_blocks(1).unwrap();

    // === 11. Assert withdraw output pays operator deposit_size ===
    assert_eq!(withdraw_tx.output[1].value, params.deposit_size);
    assert_eq!(
        withdraw_tx.output[1].script_pubkey,
        ScriptBuf::new_p2tr(&secp, op_client.operator.pubkey, None)
    );
}

/// Operator modifies withdrawTx output after committee presigning (SIGHASH_SINGLE
/// on input 0 only commits to the OP_RETURN at output 0, not the operator payment).
#[test]
fn test_withdraw_operator_can_modify_payment_output() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xe2e);
    let network = fresh_network();

    // === Create actors ===
    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint(), [0xaa; 20]);
    let committee = Committee::new(&mut rng, &secp);
    let operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);

    // === Fund actors ===
    let request_utxo =
        network.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
    let operator_init_utxo =
        network.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    // === Wrap in client APIs ===
    let mut dep_client = DepositorClient::new(depositor, params.clone());
    let committee_client = CommitteeClient::new(committee, params.clone());
    let mut op_operator = operator;
    op_operator.init_utxo = operator_init_utxo;
    let mut op_client = OperatorClient::new(op_operator, params.clone());

    // === 1. Depositor creates request ===
    let request_tx = dep_client
        .create_request(committee_client.committee.pubkey, request_utxo)
        .unwrap();
    network.broadcast_tx(&request_tx).unwrap();
    network.mine_blocks(1).unwrap();
    let request_txid = request_tx.compute_txid();

    // === 2. Committee presigns deposit ===
    let deposit_tx = committee_client
        .presign_deposit(
            request_txid,
            dep_client.depositor.pubkey,
            dep_client.depositor.deposit_secret_hash(),
            &request_tx.output[0],
        )
        .unwrap();
    network.broadcast_tx(&deposit_tx).unwrap();
    network.mine_blocks(1).unwrap();
    let deposit_txid = deposit_tx.compute_txid();

    // === 3. Compute kickoff txid ===
    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let kickoff_txid = op_client.kickoff_txid(slot, disprove_hash).unwrap();

    // === 4. Build withdraw prevouts ===
    let connector_info =
        scripts::connector_spend_info(&secp, op_client.operator.pubkey, disprove_hash).unwrap();
    let connector_output = TxOut {
        value: params.dust_amount,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
    };
    let withdraw_prevouts = vec![deposit_tx.output[0].clone(), connector_output];

    // === 5. Committee presigns withdraw (SIGHASH_SINGLE on input 0) ===
    let presigned_withdraw = committee_client
        .presign_withdraw(
            deposit_txid,
            kickoff_txid,
            op_client.operator.pubkey,
            &withdraw_prevouts,
        )
        .unwrap();

    // === 6. Operator modifies output[1] — different address and deducts fee ===
    let mut withdraw_tx = presigned_withdraw;
    let fee = bitcoin::Amount::from_sat(10_000);
    let alt_sk = bitcoin::secp256k1::SecretKey::new(&mut rng);
    let alt_pk = alt_sk.x_only_public_key(&secp).0;
    let alt_script_pubkey = ScriptBuf::new_p2tr(&secp, alt_pk, None);
    withdraw_tx.output[1].value = params.deposit_size - fee;
    withdraw_tx.output[1].script_pubkey = alt_script_pubkey.clone();

    // Store modified tx and proceed
    op_client.receive_presigned_withdraw(withdraw_tx).unwrap();

    // === 7. Operator creates and broadcasts kickoff ===
    let proof_msg = [0xbb; lamport::MSG_LEN];
    let txs = op_client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();
    for tx in &txs {
        network.broadcast_tx(tx).unwrap();
    }
    network.mine_blocks(1).unwrap();

    // === 8. Mine kickoff_timeout blocks ===
    network
        .mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64)
        .unwrap();

    // === 9. Operator completes withdraw with modified output ===
    let withdraw_tx = op_client
        .complete_withdraw(kickoff_txid, disprove_hash, &withdraw_prevouts, &network)
        .unwrap();
    network.mine_blocks(1).unwrap();

    // === 10. Assert output[1] has modified value and different address ===
    assert_eq!(withdraw_tx.output[1].value, params.deposit_size - fee);
    assert_eq!(withdraw_tx.output[1].script_pubkey, alt_script_pubkey);

    // === 11. Alt key spends the withdraw output ===
    let withdraw_txid = withdraw_tx.compute_txid();
    let alt_keypair = Keypair::from_secret_key(&secp, &alt_sk);
    let tweaked = alt_keypair.tap_tweak(&secp, None);

    let spend_value = withdraw_tx.output[1].value - bitcoin::Amount::from_sat(1_000);
    let mut spend_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(withdraw_txid, 1),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: spend_value,
            script_pubkey: alt_script_pubkey.clone(),
        }],
    };

    let prevouts = [withdraw_tx.output[1].clone()];
    let mut cache = SighashCache::new(&spend_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();
    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
    spend_tx.input[0].witness =
        Witness::p2tr_key_spend(&bitcoin::taproot::Signature { signature: sig, sighash_type: bitcoin::sighash::TapSighashType::Default });

    network.broadcast_tx(&spend_tx).unwrap();
    network.mine_blocks(1).unwrap();
}

/// Depositor cancels when committee doesn't act (escape hatch).
#[test]
fn test_cancel_escape_hatch() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xe2e);
    let network = fresh_network();

    // === Create actors ===
    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint(), [0xaa; 20]);
    let committee = Committee::new(&mut rng, &secp);

    // === Fund depositor ===
    let request_utxo =
        network.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();

    let mut dep_client = DepositorClient::new(depositor, params.clone());

    // === 1. Depositor creates request ===
    let request_tx = dep_client
        .create_request(committee.pubkey, request_utxo)
        .unwrap();
    network.broadcast_tx(&request_tx).unwrap();
    network.mine_blocks(1).unwrap();

    // === 2. Mine deposit_timeout + 1 blocks (CSV satisfaction) ===
    network
        .mine_blocks(params.deposit_timeout.to_consensus_u32() as u64 + 1)
        .unwrap();

    // === 3. Depositor creates cancel ===
    let request_txid = request_tx.compute_txid();
    let cancel_tx = dep_client
        .create_cancel(committee.pubkey, request_txid, &request_tx.output[0])
        .unwrap();
    network.broadcast_tx(&cancel_tx).unwrap();
    network.mine_blocks(1).unwrap();

    // === 4. Assert deposit_secret in witness[1] (32 bytes) ===
    assert_eq!(cancel_tx.input[0].witness[1].len(), 32);

    // === 5. Assert cancel output pays depositor deposit_size ===
    assert_eq!(cancel_tx.output[0].value, params.deposit_size);
    assert_eq!(
        cancel_tx.output[0].script_pubkey,
        ScriptBuf::new_p2tr(&secp, dep_client.depositor.pubkey, None)
    );
}

/// Challenger detects invalid proof and burns connector, blocking withdrawal.
#[test]
fn test_fraud_proof_disprove() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xe2e);
    let network = fresh_network();

    // === Create actors ===
    let depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint(), [0xaa; 20]);
    let committee = Committee::new(&mut rng, &secp);
    let operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);

    // === Fund actors ===
    let request_utxo =
        network.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
    let operator_init_utxo =
        network.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    // === Wrap in client APIs ===
    let mut dep_client = DepositorClient::new(depositor, params.clone());
    let committee_client = CommitteeClient::new(committee, params.clone());
    let mut op_operator = operator;
    op_operator.init_utxo = operator_init_utxo;
    let mut op_client = OperatorClient::new(op_operator, params.clone());

    // === 1. Depositor creates request ===
    let request_tx = dep_client
        .create_request(committee_client.committee.pubkey, request_utxo)
        .unwrap();
    network.broadcast_tx(&request_tx).unwrap();
    network.mine_blocks(1).unwrap();
    let request_txid = request_tx.compute_txid();

    // === 2. Committee presigns deposit ===
    let deposit_tx = committee_client
        .presign_deposit(
            request_txid,
            dep_client.depositor.pubkey,
            dep_client.depositor.deposit_secret_hash(),
            &request_tx.output[0],
        )
        .unwrap();
    network.broadcast_tx(&deposit_tx).unwrap();
    network.mine_blocks(1).unwrap();
    let deposit_txid = deposit_tx.compute_txid();

    // === 3. Prepare invalid proof and compute disprove hash ===
    // MockEngine: proof[0] != 0x00 is invalid, disprove_secret = proof[0..20]
    let mut invalid_proof = [0u8; lamport::MSG_LEN];
    invalid_proof[0] = 0xFF;

    let disprove_secret: [u8; 20] = {
        let mut s = [0u8; 20];
        s.copy_from_slice(&invalid_proof[0..20]);
        s
    };
    let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();

    // === 5. Committee presigns withdraw (so operator has it ready) ===
    let slot = 0;
    let kickoff_txid = op_client.kickoff_txid(slot, disprove_hash).unwrap();

    let connector_info =
        scripts::connector_spend_info(&secp, op_client.operator.pubkey, disprove_hash).unwrap();
    let connector_output = TxOut {
        value: params.dust_amount,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
    };
    let withdraw_prevouts = vec![deposit_tx.output[0].clone(), connector_output];

    let presigned_withdraw = committee_client
        .presign_withdraw(
            deposit_txid,
            kickoff_txid,
            op_client.operator.pubkey,
            &withdraw_prevouts,
        )
        .unwrap();
    op_client
        .receive_presigned_withdraw(presigned_withdraw)
        .unwrap();

    // === 6. Operator creates kickoff with invalid proof (with fanout path) ===
    let txs = op_client
        .create_kickoff(slot, disprove_hash, &invalid_proof)
        .unwrap();
    let kickoff_tx = txs.last().unwrap();
    assert_eq!(kickoff_tx.compute_txid(), kickoff_txid);
    for tx in &txs {
        network.broadcast_tx(tx).unwrap();
    }
    network.mine_blocks(1).unwrap();

    // === 7. Challenger scans tip block for kickoffs ===
    let tip = network.get_chain_tip().unwrap();
    let block = network.get_block_at_height(tip).unwrap();

    let challenger = ChallengerClient::new(MockEngine, params.clone());
    let candidates = challenger.scan_block_for_kickoffs(&block);
    assert_eq!(candidates.len(), 1, "should find exactly one kickoff in block");

    // === 8. Challenger challenges the kickoff ===
    let result = challenger.challenge_kickoff(&candidates[0]).unwrap();
    assert!(result.is_some(), "challenger should detect invalid proof");

    // === 9. Broadcast disprove tx (burns connector) ===
    let disprove_tx = result.unwrap();
    network.broadcast_tx(&disprove_tx).unwrap();
    network.mine_blocks(1).unwrap();

    // === 10. Mine kickoff_timeout blocks ===
    network
        .mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64)
        .unwrap();

    // === 11. Operator's withdraw should fail (connector already spent) ===
    let withdraw_result = op_client.complete_withdraw(
        kickoff_txid,
        disprove_hash,
        &withdraw_prevouts,
        &network,
    );
    assert!(
        withdraw_result.is_err(),
        "withdraw should fail because connector was burned by disprove"
    );
}

/// Challenger ignores a valid proof (no disprove tx produced).
#[test]
fn test_challenger_ignores_valid_proof() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xe2e);
    let network = fresh_network();

    let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
    let operator_init_utxo =
        network.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();
    operator.init_utxo = operator_init_utxo;

    let mut op_client = OperatorClient::new(operator, params.clone());

    // Valid proof: proof[0] = 0x00 → MockEngine returns None
    let slot = 0;
    let proof_msg = [0u8; lamport::MSG_LEN];
    let disprove_hash = [0xaa; 32];

    let txs = op_client
        .create_kickoff(slot, disprove_hash, &proof_msg)
        .unwrap();
    for tx in &txs {
        network.broadcast_tx(tx).unwrap();
    }
    network.mine_blocks(1).unwrap();

    // Challenger scans tip block
    let tip = network.get_chain_tip().unwrap();
    let block = network.get_block_at_height(tip).unwrap();

    let challenger = ChallengerClient::new(MockEngine, params);
    let candidates = challenger.scan_block_for_kickoffs(&block);
    assert_eq!(candidates.len(), 1);

    let result = challenger.challenge_kickoff(&candidates[0]).unwrap();
    assert!(result.is_none(), "challenger should ignore valid proof");
}

/// Verify extract_proof_from_kickoff roundtrip: build+sign a kickoff,
/// then extract proof data from the signed witness.
#[test]
fn test_extract_proof_from_kickoff() {
    let secp = Secp256k1::new();
    let params = Params::test_defaults();
    let mut rng = test_rng_seeded(0xe2e);
    let network = fresh_network();

    let mut operator = Operator::new(
        &mut rng,
        &secp,
        OutPoint::new(Txid::all_zeros(), 0),
        params.deposit_count,
    );
    operator.init_utxo =
        network.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

    let mut tree = operator::fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
    let init_txout = TxOut {
        value: params.fanout_init_value(),
        script_pubkey: ScriptBuf::new_p2tr(&secp, operator.pubkey, None),
    };
    operator::fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params)
        .unwrap();

    for level in &tree.levels {
        for tx in level {
            network.broadcast_tx(tx).unwrap();
        }
    }
    network.mine_blocks(1).unwrap();

    let slot = 0;
    let disprove_hash = [0xaa; 32];
    let mut tx =
        operator::kickoff::build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params)
            .unwrap();

    let msg = [0xbb; lamport::MSG_LEN];
    let lamport_sig = operator.lamport_keys[slot].sign(&msg);
    let lamport_pk = operator.lamport_pubkey(slot).unwrap();
    let prevouts = tree.kickoff_prevouts(&params, slot).unwrap();

    operator::kickoff::sign_kickoff_tx(
        &secp,
        &mut tx,
        &operator.keypair,
        &lamport_sig,
        &lamport_pk,
        &prevouts,
        &params,
    )
    .unwrap();

    network.broadcast_tx(&tx).unwrap();
    network.mine_blocks(1).unwrap();

    let data = challenger::kickoff::extract_proof_from_kickoff(&tx, &params).unwrap();
    assert_eq!(data.operator_pubkey, operator.pubkey);
    assert_eq!(data.proof, msg);
    assert_eq!(data.lamport_pk.0, lamport_pk.0);
}
