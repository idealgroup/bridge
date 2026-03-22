use bitcoin::absolute::LockTime;
use bitcoin::taproot::{LeafVersion, TaprootSpendInfo};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, ScriptBuf, Txid, Witness};

use crate::scripts;
use crate::BridgeError;

/// Builds an unsigned disprove transaction.
///
/// - Input: kickoffTx.out[0] (connector), script-path with hash preimage (no sig)
/// - Output: OP_RETURN (burns the connector)
pub fn build_disprove_tx(kickoff_txid: Txid) -> Transaction {
    // Pad OP_RETURN to meet MIN_STANDARD_TX_NONWITNESS_SIZE (65 bytes).
    let op_return = ScriptBuf::new_op_return([0u8; 4]);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::new(kickoff_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return,
        }],
    }
}

/// Attaches the script-path witness (hash preimage, no signature) to a disprove tx.
pub fn witness_disprove_tx(
    tx: &mut Transaction,
    disprove_secret: [u8; 20],
    disprove_secret_hash: [u8; 32],
    connector_spend_info: &TaprootSpendInfo,
) -> Result<(), BridgeError> {
    let leaf_script = scripts::disprove_script(disprove_secret_hash);
    let control_block = connector_spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .ok_or(BridgeError::Signing("disprove leaf not in taproot tree".into()))?;

    let mut witness = Witness::new();
    witness.push(disprove_secret);
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[0].witness = witness;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::Secp256k1;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_disprove_tx() {
        let kickoff_txid = Txid::all_zeros();
        let tx = build_disprove_tx(kickoff_txid);

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output.vout, 0);
        assert!(tx.input[0].witness.is_empty());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::ZERO);
        assert!(tx.output[0].script_pubkey.is_op_return());
    }

    #[test]
    fn test_witness_disprove_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = crate::params::Params::test_defaults();

        use crate::actor::Operator;
        use crate::network::BITCOIN_NETWORK;
        use crate::transactions::{fanout, kickoff};

        let mut operator = Operator::new(&mut rng, &secp, bitcoin::OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

        let mut tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: bitcoin::Address::p2tr(&secp, operator.pubkey, None, bitcoin::Network::Bitcoin)
                .script_pubkey(),
        };
        fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let secret = [0xab; 20];
        let secret_hash = sha256::Hash::hash(&secret).to_byte_array();

        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, secret_hash, &params,
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
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let kickoff_txid = kickoff_tx.compute_txid();
        let spend_info = scripts::connector_spend_info(
            &secp, operator.pubkey, secret_hash,
        ).unwrap();

        let mut tx = build_disprove_tx(kickoff_txid);
        witness_disprove_tx(&mut tx, secret, secret_hash, &spend_info).unwrap();

        assert_eq!(tx.input[0].witness.len(), 3);
        assert_eq!(tx.input[0].witness[0], secret);

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_disprove_wrong_preimage_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = crate::params::Params::test_defaults();

        use crate::actor::Operator;
        use crate::network::BITCOIN_NETWORK;
        use crate::transactions::{fanout, kickoff};

        let mut operator = Operator::new(&mut rng, &secp, bitcoin::OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

        let mut tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: bitcoin::Address::p2tr(&secp, operator.pubkey, None, bitcoin::Network::Bitcoin)
                .script_pubkey(),
        };
        fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let secret = [0xab; 20];
        let secret_hash = sha256::Hash::hash(&secret).to_byte_array();

        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, secret_hash, &params,
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
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let kickoff_txid = kickoff_tx.compute_txid();
        let spend_info = scripts::connector_spend_info(
            &secp, operator.pubkey, secret_hash,
        ).unwrap();

        let mut tx = build_disprove_tx(kickoff_txid);

        // Use wrong preimage
        let wrong_secret = [0xcc; 20];
        witness_disprove_tx(&mut tx, wrong_secret, secret_hash, &spend_info).unwrap();

        assert!(
            BITCOIN_NETWORK.broadcast_tx(&tx).is_err(),
            "wrong hash preimage should be rejected"
        );
    }
}
