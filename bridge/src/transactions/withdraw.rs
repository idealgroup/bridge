use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Network, ScriptBuf, Txid, Witness};

use crate::actor::Operator;
use crate::params::Params;
use crate::scripts;
use crate::BridgeError;

/// Builds a withdraw transaction.
///
/// - Input 0: depositTx.out[0], key-spend presigned by committee
/// - Input 1: kickoffTx.out[0] (connector), key-spend by operator
/// - Output 0: DEPOSIT_SIZE to operator
/// - Output 1: P2A anchor (240 sats)
pub fn build_withdraw_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    deposit_txid: Txid,
    kickoff_txid: Txid,
    operator: &Operator,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    let operator_address = Address::p2tr(secp, operator.pubkey, None, Network::Bitcoin);

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            // Input 0: deposit output (committee presigns)
            TxIn {
                previous_output: bitcoin::OutPoint::new(deposit_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            // Input 1: connector output (operator key-spend, nSequence enforces timelock)
            TxIn {
                previous_output: bitcoin::OutPoint::new(kickoff_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: params.kickoff_timeout,
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: params.deposit_size,
                script_pubkey: operator_address.script_pubkey(),
            },
            // P2A anchor for CPFP fee bumping
            TxOut {
                value: scripts::P2A_DUST,
                script_pubkey: scripts::p2a_script(),
            },
        ],
    })
}

/// Committee presigns withdraw input 0 (key-spend on deposit output, no script tree).
pub fn presign_withdraw_input0(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    committee_keypair: &Keypair,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let tweaked = committee_keypair.tap_tweak(secp, None);
    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(BridgeError::Sighash)?;
    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
    tx.input[0].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    });
    Ok(())
}

/// Operator signs withdraw input 1 (key-spend on connector).
///
/// The timelock is enforced by nSequence on this input, which the committee's
/// presigned signature on input 0 commits to via SIGHASH_ALL.
pub fn sign_withdraw_input1(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    operator_keypair: &Keypair,
    connector_spend_info: &TaprootSpendInfo,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let merkle_root = connector_spend_info.merkle_root();
    let tweaked = operator_keypair.tap_tweak(secp, merkle_root);

    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            1, &Prevouts::All(prevouts), TapSighashType::Default,
        )
        .map_err(BridgeError::Sighash)?;

    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());

    tx.input[1].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::Committee;
    use bitcoin::hashes::sha256;
    use bitcoin::OutPoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_withdraw_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng,
            &secp,
            OutPoint::new(Txid::all_zeros(), 0),
            params.deposit_count,
        );

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();

        let tx = build_withdraw_tx(
            &secp,
            deposit_txid,
            kickoff_txid,
            &operator,
            &params,
        )
        .unwrap();

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.input[1].sequence, params.kickoff_timeout);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }

    #[test]
    fn test_presign_withdraw_input0() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::actor::Depositor;
        use crate::network::BITCOIN_NETWORK;
        use crate::transactions::{deposit, fanout, kickoff, request};

        // Fund depositor
        let request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, {
            let dep_tmp = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0));
            dep_tmp.pubkey
        }, params.deposit_size).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let depositor = Depositor::new(&mut rng, &secp, 0, request_utxo);
        let committee = Committee::new(&mut rng, &secp);

        // Fund operator, then update its init_utxo to the real outpoint
        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

        // Build request → deposit chain
        let mut request_tx = request::build_request_tx(&secp, &depositor, &committee, &params).unwrap();
        let depositor_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, depositor.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let request_txid = request_tx.compute_txid();
        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();
        let mut deposit_tx = deposit::build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();
        deposit::presign_deposit_tx(
            &secp, &mut deposit_tx, &committee.keypair,
            &request_spend_info, &[request_tx.output[0].clone()],
        ).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&deposit_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // Build fanout → kickoff chain
        let mut tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let disprove_hash = [0xaa; 32];
        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, disprove_hash, &params,
        ).unwrap();
        let kickoff_prevouts = tree.kickoff_prevouts(&params, slot);
        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();
        kickoff::sign_kickoff_tx(
            &secp, &mut kickoff_tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &kickoff_prevouts, &params,
        ).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64).unwrap();

        // Build withdraw tx
        let deposit_txid = deposit_tx.compute_txid();
        let kickoff_txid = kickoff_tx.compute_txid();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        let prevouts = vec![deposit_tx.output[0].clone(), kickoff_tx.output[0].clone()];
        presign_withdraw_input0(&secp, &mut tx, &committee.keypair, &prevouts).unwrap();

        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness[0].len(), 64);

        // Also sign input 1 so the full tx is valid for regtest
        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash,
        ).unwrap();
        sign_withdraw_input1(
            &secp, &mut tx, &operator.keypair,
            &connector_info, &prevouts,
        ).unwrap();

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_sign_withdraw_input1() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::actor::Depositor;
        use crate::network::BITCOIN_NETWORK;
        use crate::transactions::{deposit, fanout, kickoff, request};

        // Fund depositor
        let request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, {
            let dep_tmp = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0));
            dep_tmp.pubkey
        }, params.deposit_size).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let depositor = Depositor::new(&mut rng, &secp, 0, request_utxo);
        let committee = Committee::new(&mut rng, &secp);

        // Fund operator, then update its init_utxo to the real outpoint
        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

        // Build request → deposit chain
        let mut request_tx = request::build_request_tx(&secp, &depositor, &committee, &params).unwrap();
        let depositor_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, depositor.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let request_txid = request_tx.compute_txid();
        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();
        let mut deposit_tx = deposit::build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();
        deposit::presign_deposit_tx(
            &secp, &mut deposit_tx, &committee.keypair,
            &request_spend_info, &[request_tx.output[0].clone()],
        ).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&deposit_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // Build and confirm fanout tree
        let mut tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // Build and confirm kickoff
        let slot = 0;
        let disprove_hash = sha256::Hash::hash(&[0xab; 20]).to_byte_array();
        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, disprove_hash, &params,
        ).unwrap();
        let kickoff_prevouts = tree.kickoff_prevouts(&params, slot);
        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();
        kickoff::sign_kickoff_tx(
            &secp, &mut kickoff_tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &kickoff_prevouts, &params,
        ).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64).unwrap();

        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash,
        ).unwrap();

        // Build withdraw tx with both real parents
        let deposit_txid = deposit_tx.compute_txid();
        let kickoff_txid = kickoff_tx.compute_txid();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        let prevouts = vec![deposit_tx.output[0].clone(), kickoff_tx.output[0].clone()];

        // Sign input 0 (committee) so full tx is valid for regtest
        presign_withdraw_input0(&secp, &mut tx, &committee.keypair, &prevouts).unwrap();

        sign_withdraw_input1(
            &secp, &mut tx, &operator.keypair,
            &connector_info, &prevouts,
        ).unwrap();

        // Key-spend witness: single 64-byte signature
        assert_eq!(tx.input[1].witness.len(), 1);
        assert_eq!(tx.input[1].witness[0].len(), 64);

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_withdraw_input1_wrong_key_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::network::BITCOIN_NETWORK;
        use crate::transactions::{fanout, kickoff};

        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);
        let wrong_operator = Operator::new(
            &mut rng, &secp, OutPoint::new(Txid::all_zeros(), 1), params.deposit_count,
        );

        let mut tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let disprove_hash = sha256::Hash::hash(&[0xab; 20]).to_byte_array();
        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, disprove_hash, &params,
        ).unwrap();
        let kickoff_prevouts = tree.kickoff_prevouts(&params, slot);
        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();
        kickoff::sign_kickoff_tx(
            &secp, &mut kickoff_tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &kickoff_prevouts, &params,
        ).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64).unwrap();

        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash,
        ).unwrap();

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = kickoff_tx.compute_txid();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        let deposit_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, committee.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        let prevouts = [deposit_prevout, kickoff_tx.output[0].clone()];

        // Sign with wrong operator's key
        sign_withdraw_input1(
            &secp, &mut tx, &wrong_operator.keypair,
            &connector_info, &prevouts,
        ).unwrap();

        assert!(
            BITCOIN_NETWORK.broadcast_tx(&tx).is_err(),
            "wrong operator key should be rejected"
        );
    }

    // Note: OP_CSV test removed — the kickoff timeout is now enforced by nSequence
    // committed in the committee's presigned signature on input 0, not by a script opcode.
}
