use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, ScriptBuf, Witness};

use crate::actor::Operator;
use crate::params::Params;
use crate::scripts;
use crate::transactions::fanout::FanoutTree;
use crate::BridgeError;

/// Builds a kickoff transaction for a given deposit slot.
///
/// - 3 inputs: fanout leaf UTXOs (one per Lamport chunk), script-path spend
/// - 2 outputs: [0] connector (P2TR with withdraw/disprove leaves), [1] P2A anchor
pub fn build_kickoff_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    operator: &Operator,
    slot: usize,
    fanout_tree: &FanoutTree,
    disprove_secret_hash: [u8; 20],
    params: &Params,
) -> Result<Transaction, BridgeError> {
    if slot >= params.deposit_count {
        return Err(BridgeError::IndexOutOfRange {
            name: "slot",
            index: slot,
            max: params.deposit_count,
        });
    }

    // 3 inputs: one per Lamport chunk
    let inputs: Vec<TxIn> = (0..params.lamport_chunks_per_slot)
        .map(|chunk| {
            let outpoint = fanout_tree.leaf_outpoint(params, slot, chunk);
            TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }
        })
        .collect();

    // Output 0: connector
    let connector_info = scripts::connector_spend_info(
        secp,
        operator.pubkey,
        disprove_secret_hash,
        params.kickoff_timeout,
    )?;
    let connector_output = TxOut {
        value: params.dust_amount,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
    };

    // Output 1: P2A anchor (OP_TRUE for CPFP fee bumping)
    let anchor_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(&[]),
    };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![connector_output, anchor_output],
    })
}

/// Signs the kickoff transaction (3 script-path inputs: operator sig + lamport signature).
pub fn sign_kickoff_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    operator_keypair: &Keypair,
    lamport_sig: &lamport::Signature,
    lamport_pk: &lamport::PublicKey,
    prevouts: &[TxOut],
    params: &Params,
) -> Result<(), BridgeError> {
    let operator_pubkey = operator_keypair.x_only_public_key().0;

    for chunk in 0..params.lamport_chunks_per_slot {
        let (start, end) = params.lamport_chunk_range(chunk);

        let leaf_script = scripts::fanout_leaf_script(
            operator_pubkey, lamport_pk, start, end,
        );
        let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
            &leaf_script, LeafVersion::TapScript,
        );

        let spend_info = scripts::fanout_leaf_spend_info(
            secp, operator_pubkey, lamport_pk, start, end,
        )?;
        let control_block = spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
            .ok_or(BridgeError::Signing("fanout leaf not in taproot tree".into()))?;

        let mut cache = SighashCache::new(&*tx);
        let sighash = cache
            .taproot_script_spend_signature_hash(
                chunk, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default,
            )
            .map_err(BridgeError::Sighash)?;

        let msg = Message::from_digest(*sighash.as_byte_array());
        // Script-path: sign with untweaked keypair
        let sig = secp.sign_schnorr_no_aux_rand(&msg, operator_keypair);

        let mut witness = Witness::new();
        // Lamport preimages (reversed order for script processing)
        let preimages = lamport_sig.witness_data_for_range(start, end);
        for preimage in &preimages {
            witness.push(preimage);
        }
        // Schnorr signature
        let sig_obj = bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };
        witness.push(sig_obj.to_vec());
        // Script and control block
        witness.push(leaf_script.as_bytes());
        witness.push(control_block.serialize());

        tx.input[chunk].witness = witness;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::Operator;
    use crate::params::Params;
    use crate::transactions::fanout;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_kickoff_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);
        let tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();

        let disprove_hash = [0xaa; 20];
        let tx = build_kickoff_tx(&secp, &operator, 0, &tree, disprove_hash, &params).unwrap();

        assert_eq!(tx.input.len(), 3);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, params.dust_amount);
    }

    #[test]
    fn test_sign_kickoff_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);
        let tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();

        let slot = 0;
        let disprove_hash = [0xaa; 20];
        let mut tx = build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params).unwrap();

        // Sign a test message with the lamport key
        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot);

        // Build prevouts for the 3 inputs (fanout leaf outputs)
        let prevouts: Vec<TxOut> = (0..params.lamport_chunks_per_slot)
            .map(|chunk| {
                let leaf_level = &tree.levels[tree.levels.len() - 1];
                let tx_index = slot / params.fanout_branching;
                let output_index = (slot % params.fanout_branching) * params.lamport_chunks_per_slot + chunk;
                leaf_level[tx_index].output[output_index].clone()
            })
            .collect();

        sign_kickoff_tx(
            &secp, &mut tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &prevouts, &params,
        ).unwrap();

        // Each of the 3 inputs should have witness: lamport preimages + sig + script + control_block
        for chunk in 0..params.lamport_chunks_per_slot {
            let (start, end) = params.lamport_chunk_range(chunk);
            let expected_len = (end - start) + 3; // preimages + sig + script + cb
            assert_eq!(tx.input[chunk].witness.len(), expected_len);
            // Sig is the element right before script and control_block
            let sig_idx = expected_len - 3;
            assert_eq!(tx.input[chunk].witness[sig_idx].len(), 64);
        }

        use crate::network::BITCOIN_NETWORK;
        for i in 0..params.lamport_chunks_per_slot {
            BITCOIN_NETWORK.verify_input(&tx, i, &prevouts).unwrap();
        }
    }

    #[test]
    fn test_kickoff_slot_out_of_range() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);
        let tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();

        let result = build_kickoff_tx(&secp, &operator, 999, &tree, [0; 20], &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_kickoff_wrong_lamport_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);
        let tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();

        let slot = 0;
        let disprove_hash = [0xaa; 20];
        let mut tx = build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params).unwrap();

        // Sign with a DIFFERENT slot's Lamport key (preimages won't match slot 0's pubkey)
        let msg = [0xbb; lamport::MSG_LEN];
        let wrong_lamport_sig = operator.lamport_keys[1].sign(&msg);
        let correct_lamport_pk = operator.lamport_pubkey(slot);

        let prevouts: Vec<TxOut> = (0..params.lamport_chunks_per_slot)
            .map(|chunk| {
                let leaf_level = &tree.levels[tree.levels.len() - 1];
                let tx_index = slot / params.fanout_branching;
                let output_index = (slot % params.fanout_branching) * params.lamport_chunks_per_slot + chunk;
                leaf_level[tx_index].output[output_index].clone()
            })
            .collect();

        sign_kickoff_tx(
            &secp, &mut tx, &operator.keypair,
            &wrong_lamport_sig, &correct_lamport_pk, &prevouts, &params,
        ).unwrap();

        use crate::network::BITCOIN_NETWORK;
        let mut any_failed = false;
        for i in 0..params.lamport_chunks_per_slot {
            if BITCOIN_NETWORK.verify_input(&tx, i, &prevouts).is_err() {
                any_failed = true;
                break;
            }
        }
        assert!(any_failed, "wrong Lamport preimages should be rejected");
    }
}
