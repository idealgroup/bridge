use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{ScriptBuf, Witness};

use crate::actor::Operator;
use crate::engine::Proof;
use crate::params::Params;
use crate::scripts;
use crate::transactions::fanout::FanoutTree;
use crate::BridgeError;

/// Data extracted from a kickoff transaction's witnesses.
pub struct KickoffData {
    pub operator_pubkey: XOnlyPublicKey,
    pub proof: Proof,
    pub lamport_pk: Box<lamport::PublicKey>,
}

/// Extract proof, operator pubkey, and Lamport PK from a kickoff tx.
/// Parses leaf scripts from witness data — no external info needed.
pub fn extract_proof_from_kickoff(
    tx: &Transaction,
    params: &Params,
) -> Result<KickoffData, BridgeError> {
    let num_chunks = params.lamport_chunks_per_slot;
    if tx.input.len() != num_chunks {
        return Err(BridgeError::WitnessParse(format!(
            "expected {} inputs, got {}",
            num_chunks,
            tx.input.len()
        )));
    }

    let mut full_pk = Box::new(lamport::PublicKey(
        [[[0u8; lamport::HASH_LEN]; 2]; lamport::NUM_BITS],
    ));
    let mut all_preimages = [[0u8; lamport::PREIMAGE_LEN]; lamport::NUM_BITS];
    let mut operator_pubkey: Option<XOnlyPublicKey> = None;

    for chunk in 0..num_chunks {
        let (start, end) = params.lamport_chunk_range(chunk);
        let num_bits = end - start;
        let witness = &tx.input[chunk].witness;
        let wit_len = witness.len();

        // Witness layout: [preimages_reversed...] [sig] [leaf_script] [control_block]
        // So leaf_script is witness[wit_len - 2]
        if wit_len < 3 {
            return Err(BridgeError::WitnessParse(format!(
                "input {} witness too short ({})",
                chunk, wit_len
            )));
        }

        let num_preimages = num_bits;
        let expected_wit_len = num_preimages + 3; // preimages + sig + script + control_block
        if wit_len != expected_wit_len {
            return Err(BridgeError::WitnessParse(format!(
                "input {} witness len {}, expected {}",
                chunk, wit_len, expected_wit_len
            )));
        }

        let leaf_script = witness[wit_len - 2].to_vec();

        // Extract operator pubkey from leaf script
        // bytes[0]:     0x20 (OP_PUSHBYTES_32)
        // bytes[1..33]: operator x-only pubkey (32 bytes)
        // bytes[33]:    OP_CHECKSIGVERIFY
        if leaf_script.len() < 34 {
            return Err(BridgeError::WitnessParse(
                "leaf script too short for operator pubkey".into(),
            ));
        }
        if leaf_script[0] != 0x20 {
            return Err(BridgeError::WitnessParse(format!(
                "expected OP_PUSHBYTES_32 (0x20) at script[0], got 0x{:02x}",
                leaf_script[0]
            )));
        }
        let chunk_op_pk = XOnlyPublicKey::from_slice(&leaf_script[1..33])
            .map_err(|e| BridgeError::WitnessParse(format!("operator pubkey: {e}")))?;
        match operator_pubkey {
            None => operator_pubkey = Some(chunk_op_pk),
            Some(ref prev) => {
                if *prev != chunk_op_pk {
                    return Err(BridgeError::WitnessParse(
                        "operator pubkey mismatch across chunks".into(),
                    ));
                }
            }
        }

        // Extract Lamport PK hashes from the leaf script
        // Lamport verification starts at offset 34 (after 0x20 + 32-byte pubkey + OP_CHECKSIGVERIFY)
        // Per bit: 74 bytes
        //   offset 0: OP_SHA256 (1)
        //   offset 1: OP_DUP (1)
        //   offset 2: 0x20 (OP_PUSHBYTES_32) (1)
        //   offset 3..35: pk[i][0] (32)
        //   offset 35: OP_EQUAL (1)
        //   offset 36: OP_IF (1)
        //   offset 37: OP_DROP (1)
        //   offset 38: OP_ELSE (1)
        //   offset 39: 0x20 (OP_PUSHBYTES_32) (1)
        //   offset 40..72: pk[i][1] (32)
        //   offset 72: OP_EQUALVERIFY (1)
        //   offset 73: OP_ENDIF (1)
        let lamport_offset = 34;
        let bytes_per_bit = 74;

        for bit_idx in 0..num_bits {
            let global_bit = start + bit_idx;
            let base = lamport_offset + bit_idx * bytes_per_bit;
            if base + bytes_per_bit > leaf_script.len() {
                return Err(BridgeError::WitnessParse(format!(
                    "leaf script too short for bit {}",
                    global_bit
                )));
            }
            full_pk.0[global_bit][0]
                .copy_from_slice(&leaf_script[base + 3..base + 35]);
            full_pk.0[global_bit][1]
                .copy_from_slice(&leaf_script[base + 40..base + 72]);
        }

        // Extract preimages from witness[0..num_preimages], they are in reversed order
        for i in 0..num_preimages {
            let preimage = witness[i].to_vec();
            if preimage.len() != lamport::PREIMAGE_LEN {
                return Err(BridgeError::WitnessParse(format!(
                    "preimage {} wrong length {} (expected {})",
                    i,
                    preimage.len(),
                    lamport::PREIMAGE_LEN
                )));
            }
            // Witness is reversed: witness[0] is the last bit's preimage
            let global_bit = start + (num_preimages - 1 - i);
            all_preimages[global_bit].copy_from_slice(&preimage);
        }
    }

    let operator_pubkey = operator_pubkey
        .ok_or_else(|| BridgeError::WitnessParse("no operator pubkey found".into()))?;

    // Recover the message (proof) from preimages + PK
    let proof_msg = full_pk
        .recover_message(&all_preimages)
        .map_err(|e| BridgeError::WitnessParse(format!("recover_message: {e}")))?;

    Ok(KickoffData {
        operator_pubkey,
        proof: proof_msg,
        lamport_pk: full_pk,
    })
}

/// Builds a kickoff transaction for a given deposit slot.
///
/// - 3 inputs: fanout leaf UTXOs (one per Lamport chunk), script-path spend
/// - 2 outputs: [0] connector (P2TR with withdraw/disprove leaves), [1] P2A anchor
pub fn build_kickoff_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    operator: &Operator,
    slot: usize,
    fanout_tree: &FanoutTree,
    disprove_secret_hash: [u8; 32],
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
    )?;
    let connector_output = TxOut {
        value: params.dust_amount,
        script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
    };

    // Output 1: P2A anchor for CPFP fee bumping
    let anchor_output = TxOut {
        value: scripts::P2A_DUST,
        script_pubkey: scripts::p2a_script(),
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
        )?;
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
        let preimages = lamport_sig
            .witness_data_for_range(start, end)
            .map_err(|e| BridgeError::Signing(format!("lamport: {e}")))?;
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

        let disprove_hash = [0xaa; 32];
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

        use crate::network::BITCOIN_NETWORK;

        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

        let mut tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: bitcoin::Address::p2tr(&secp, operator.pubkey, None, bitcoin::Network::Bitcoin)
                .script_pubkey(),
        };
        fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();

        // Confirm fanout tree
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let disprove_hash = [0xaa; 32];
        let mut tx = build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params).unwrap();

        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();

        let prevouts = tree.kickoff_prevouts(&params, slot);

        sign_kickoff_tx(
            &secp, &mut tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &prevouts, &params,
        ).unwrap();

        for chunk in 0..params.lamport_chunks_per_slot {
            let (start, end) = params.lamport_chunk_range(chunk);
            let expected_len = (end - start) + 3;
            assert_eq!(tx.input[chunk].witness.len(), expected_len);
            let sig_idx = expected_len - 3;
            assert_eq!(tx.input[chunk].witness[sig_idx].len(), 64);
        }

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_extract_proof_from_kickoff() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::network::BITCOIN_NETWORK;

        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
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
        let disprove_hash = [0xaa; 32];
        let mut tx = build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params).unwrap();

        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();

        let prevouts = tree.kickoff_prevouts(&params, slot);

        sign_kickoff_tx(
            &secp, &mut tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &prevouts, &params,
        ).unwrap();

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // Extract proof from the signed kickoff tx
        let data = extract_proof_from_kickoff(&tx, &params).unwrap();
        assert_eq!(data.operator_pubkey, operator.pubkey);
        assert_eq!(data.proof, msg);
        assert_eq!(data.lamport_pk.0, lamport_pk.0);
    }

    #[test]
    fn test_kickoff_slot_out_of_range() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);
        let tree = fanout::build_fanout_tree(&secp, &operator, &params).unwrap();

        let result = build_kickoff_tx(&secp, &operator, 999, &tree, [0; 32], &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_kickoff_wrong_lamport_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::network::BITCOIN_NETWORK;

        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
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
        let disprove_hash = [0xaa; 32];
        let mut tx = build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params).unwrap();

        // Sign with a DIFFERENT slot's Lamport key (preimages won't match slot 0's pubkey)
        let msg = [0xbb; lamport::MSG_LEN];
        let wrong_lamport_sig = operator.lamport_keys[1].sign(&msg);
        let correct_lamport_pk = operator.lamport_pubkey(slot).unwrap();

        let prevouts = tree.kickoff_prevouts(&params, slot);

        sign_kickoff_tx(
            &secp, &mut tx, &operator.keypair,
            &wrong_lamport_sig, &correct_lamport_pk, &prevouts, &params,
        ).unwrap();

        assert!(
            BITCOIN_NETWORK.broadcast_tx(&tx).is_err(),
            "wrong Lamport preimages should be rejected"
        );
    }
}
