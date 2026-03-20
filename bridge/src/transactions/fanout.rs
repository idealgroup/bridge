use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Witness};

use crate::actor::Operator;
use crate::params::Params;
use crate::scripts;
use crate::BridgeError;

/// Tree of fanout transactions expanding one operator UTXO into many leaf outputs.
pub struct FanoutTree {
    /// levels[depth][node_index] — depth 0 is the root.
    pub levels: Vec<Vec<Transaction>>,
}

impl FanoutTree {
    /// Returns the outpoint for a given deposit slot and Lamport chunk.
    pub fn leaf_outpoint(&self, params: &Params, slot: usize, chunk: usize) -> OutPoint {
        let leaf_level = &self.levels[self.levels.len() - 1];
        let tx_index = slot / params.fanout_branching;
        let output_index = (slot % params.fanout_branching) * params.lamport_chunks_per_slot + chunk;
        let txid = leaf_level[tx_index].compute_txid();
        OutPoint::new(txid, output_index as u32)
    }

    /// Returns the prevouts needed to sign/verify a kickoff transaction for a given slot.
    pub fn kickoff_prevouts(&self, params: &Params, slot: usize) -> Vec<TxOut> {
        let leaf_level = &self.levels[self.levels.len() - 1];
        let tx_index = slot / params.fanout_branching;
        (0..params.lamport_chunks_per_slot)
            .map(|chunk| {
                let output_index = (slot % params.fanout_branching) * params.lamport_chunks_per_slot + chunk;
                leaf_level[tx_index].output[output_index].clone()
            })
            .collect()
    }
}

/// Builds the complete fanout tree for an operator.
pub fn build_fanout_tree(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    operator: &Operator,
    params: &Params,
) -> Result<FanoutTree, BridgeError> {
    let mut levels: Vec<Vec<Transaction>> = Vec::with_capacity(params.fanout_depth);

    // Level 0 (root): single tx spending operator's init_utxo
    let root_output_value = params.fanout_output_value(0);
    let root_tx = build_intermediate_tx(secp, operator.init_utxo, operator.pubkey, params, root_output_value);
    levels.push(vec![root_tx]);

    // Intermediate levels (1..depth-1)
    for depth in 1..params.fanout_depth {
        let parent_level = &levels[depth - 1];
        let mut current_level = Vec::new();

        for (parent_idx, parent_tx) in parent_level.iter().enumerate() {
            let parent_txid = parent_tx.compute_txid();
            for output_idx in 0..params.fanout_branching {
                let outpoint = OutPoint::new(parent_txid, output_idx as u32);

                if depth == params.fanout_depth - 1 {
                    // Leaf level: outputs have Lamport scripts
                    let leaf_tx_idx = parent_idx * params.fanout_branching + output_idx;
                    let tx = build_leaf_tx(
                        secp, outpoint, operator, params, leaf_tx_idx,
                    )?;
                    current_level.push(tx);
                } else {
                    let output_value = params.fanout_output_value(depth);
                    let tx = build_intermediate_tx(secp, outpoint, operator.pubkey, params, output_value);
                    current_level.push(tx);
                }
            }
        }
        levels.push(current_level);
    }

    Ok(FanoutTree { levels })
}

/// Signs every transaction in the fanout tree (operator key-spend, no script tree).
pub fn sign_fanout_tree(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tree: &mut FanoutTree,
    operator_keypair: &Keypair,
    init_utxo_txout: &TxOut,
    params: &Params,
) -> Result<(), BridgeError> {
    let tweaked = operator_keypair.tap_tweak(secp, None);

    // Level 0: single root tx, prevout is init_utxo_txout
    {
        let prevouts = [init_utxo_txout.clone()];
        let tx = &mut tree.levels[0][0];
        let mut cache = SighashCache::new(&*tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(BridgeError::Sighash)?;
        let msg = Message::from_digest(*sighash.as_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
        tx.input[0].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        });
    }

    // Deeper levels: prevout comes from parent level output
    for depth in 1..tree.levels.len() {
        let parent_outputs: Vec<Vec<TxOut>> = tree.levels[depth - 1]
            .iter()
            .map(|tx| tx.output.clone())
            .collect();

        let level_len = tree.levels[depth].len();
        for node_idx in 0..level_len {
            let parent_idx = node_idx / params.fanout_branching;
            let output_idx = node_idx % params.fanout_branching;
            let prevout = parent_outputs[parent_idx][output_idx].clone();

            let tx = &mut tree.levels[depth][node_idx];
            let prevouts = [prevout];
            let mut cache = SighashCache::new(&*tx);
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .map_err(BridgeError::Sighash)?;
            let msg = Message::from_digest(*sighash.as_byte_array());
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
            tx.input[0].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });
        }
    }

    Ok(())
}

fn build_intermediate_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    input: OutPoint,
    operator_pubkey: XOnlyPublicKey,
    params: &Params,
    output_value: bitcoin::Amount,
) -> Transaction {
    let address = Address::p2tr(secp, operator_pubkey, None, Network::Bitcoin);

    let outputs: Vec<TxOut> = (0..params.fanout_branching)
        .map(|_| TxOut {
            value: output_value,
            script_pubkey: address.script_pubkey(),
        })
        .collect();

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: input,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn build_leaf_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    input: OutPoint,
    operator: &Operator,
    params: &Params,
    leaf_tx_idx: usize,
) -> Result<Transaction, BridgeError> {
    let slots_start = leaf_tx_idx * params.fanout_branching;
    let slots_end = (slots_start + params.fanout_branching).min(params.deposit_count);

    let mut outputs = Vec::new();
    for slot in slots_start..slots_end {
        let lamport_pk = operator.lamport_pubkey(slot)?;
        for chunk in 0..params.lamport_chunks_per_slot {
            let (start, end) = params.lamport_chunk_range(chunk);
            let spend_info = scripts::fanout_leaf_spend_info(
                secp,
                operator.pubkey,
                &lamport_pk,
                start,
                end,
            )?;
            let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
            outputs.push(TxOut {
                value: params.dust_amount,
                script_pubkey,
            });
        }
    }

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: input,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::Operator;
    use crate::params::Params;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn test_fanout_tree_structure() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let params = Params::test_defaults(); // m=2, L=2, 4 deposits
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);

        let tree = build_fanout_tree(&secp, &operator, &params).unwrap();

        // 2 levels: root + leaves
        assert_eq!(tree.levels.len(), 2);
        // Root: 1 tx with m=2 outputs
        assert_eq!(tree.levels[0].len(), 1);
        assert_eq!(tree.levels[0][0].output.len(), params.fanout_branching);
        // Leaf level: m=2 txs
        assert_eq!(tree.levels[1].len(), 2);
        // Each leaf tx: 2 slots * 3 chunks = 6 outputs
        assert_eq!(
            tree.levels[1][0].output.len(),
            params.fanout_branching * params.lamport_chunks_per_slot
        );
    }

    #[test]
    fn test_sign_fanout_tree() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let params = Params::test_defaults();

        use crate::network::BITCOIN_NETWORK;

        let mut operator = Operator::new(&mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value());

        let mut tree = build_fanout_tree(&secp, &operator, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        sign_fanout_tree(&secp, &mut tree, &operator.keypair, &init_txout, &params).unwrap();

        // Every tx in the tree should have a non-empty witness (1 element for key-spend)
        for level in &tree.levels {
            for tx in level {
                assert_eq!(tx.input[0].witness.len(), 1);
                // Schnorr sig is 64 bytes (Default sighash = no appended byte)
                assert_eq!(tx.input[0].witness[0].len(), 64);
            }
        }

        // Verify root tx key-spend against init_txout (auto-broadcasts in regtest)
        BITCOIN_NETWORK
            .verify_input(&tree.levels[0][0], 0, &[init_txout.clone()])
            .unwrap();

        // Verify all deeper levels against parent outputs
        for depth in 1..tree.levels.len() {
            for node_idx in 0..tree.levels[depth].len() {
                let parent_idx = node_idx / params.fanout_branching;
                let output_idx = node_idx % params.fanout_branching;
                let prevout = tree.levels[depth - 1][parent_idx].output[output_idx].clone();
                BITCOIN_NETWORK
                    .verify_input(&tree.levels[depth][node_idx], 0, &[prevout])
                    .unwrap();
            }
        }
    }

    #[test]
    fn test_leaf_outpoints() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);

        let tree = build_fanout_tree(&secp, &operator, &params).unwrap();

        // Slot 0, chunk 0 -> leaf tx 0, output 0
        let op = tree.leaf_outpoint(&params, 0, 0);
        assert_eq!(op.vout, 0);

        // Slot 0, chunk 2 -> leaf tx 0, output 2
        let op = tree.leaf_outpoint(&params, 0, 2);
        assert_eq!(op.vout, 2);

        // Slot 1, chunk 0 -> leaf tx 0, output 3
        let op = tree.leaf_outpoint(&params, 1, 0);
        assert_eq!(op.vout, 3);

        // Slot 2, chunk 0 -> leaf tx 1, output 0
        let op = tree.leaf_outpoint(&params, 2, 0);
        assert_eq!(op.vout, 0);
    }

    #[test]
    #[cfg_attr(feature = "regtest", ignore)]
    fn test_fanout_wrong_key_rejected() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let params = Params::test_defaults();
        let init_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let operator_a = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);

        let mut tree = build_fanout_tree(&secp, &operator_a, &params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator_a.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        sign_fanout_tree(&secp, &mut tree, &operator_a.keypair, &init_txout, &params).unwrap();

        // Construct prevout with a different operator's pubkey
        let init_utxo_b = OutPoint::new(Txid::all_zeros(), 1);
        let operator_b = Operator::new(&mut rng, &secp, init_utxo_b, params.deposit_count);
        let wrong_prevout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator_b.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };

        use crate::network::BITCOIN_NETWORK;
        assert!(
            BITCOIN_NETWORK.verify_input(&tree.levels[0][0], 0, &[wrong_prevout]).is_err(),
            "key-spend with wrong key should be rejected"
        );
    }
}
