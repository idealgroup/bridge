use bitcoin::key::UntweakedPublicKey as XOnlyPublicKey;
use bitcoin::transaction::Transaction;

use bridge::engine::Proof;
use bridge::params::Params;
use bridge::BridgeError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::TxOut;
    use bitcoin::OutPoint;
    use bitcoin::Txid;

    use bridge::actor::Operator;
    use bridge::network::BITCOIN_NETWORK;
    use bridge::params::Params;
    use bridge::test_support::test_rng;

    #[test]
    fn test_extract_proof_from_kickoff() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let params = Params::test_defaults();

        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();

        let mut tree = operator::fanout::build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: bitcoin::Address::p2tr(&secp, operator.pubkey, None, bitcoin::Network::Bitcoin)
                .script_pubkey(),
        };
        operator::fanout::sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();

        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let disprove_hash = [0xaa; 32];
        let mut tx = operator::kickoff::build_kickoff_tx(&secp, &operator, slot, &tree, disprove_hash, &params).unwrap();

        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();

        let prevouts = tree.kickoff_prevouts(&params, slot).unwrap();

        operator::kickoff::sign_kickoff_tx(
            &secp, &mut tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &prevouts, &params,
        ).unwrap();

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let data = extract_proof_from_kickoff(&tx, &params).unwrap();
        assert_eq!(data.operator_pubkey, operator.pubkey);
        assert_eq!(data.proof, msg);
        assert_eq!(data.lamport_pk.0, lamport_pk.0);
    }
}
