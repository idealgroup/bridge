use bitcoin::OutPoint;
use bitcoin::transaction::{Transaction, TxOut};

use crate::params::Params;
use crate::BridgeError;

/// Tree of fanout transactions expanding one operator UTXO into many leaf outputs.
pub struct FanoutTree {
    /// levels[depth][node_index] — depth 0 is the root.
    pub levels: Vec<Vec<Transaction>>,
}

impl FanoutTree {
    /// Returns the outpoint for a given deposit slot and Lamport chunk.
    pub fn leaf_outpoint(&self, params: &Params, slot: usize, chunk: usize) -> Result<OutPoint, BridgeError> {
        if slot >= params.deposit_count {
            return Err(BridgeError::IndexOutOfRange {
                name: "slot",
                index: slot,
                max: params.deposit_count,
            });
        }
        if chunk >= params.lamport_chunks_per_slot {
            return Err(BridgeError::IndexOutOfRange {
                name: "chunk",
                index: chunk,
                max: params.lamport_chunks_per_slot,
            });
        }
        let leaf_level = &self.levels[self.levels.len() - 1];
        let tx_index = slot / params.fanout_branching;
        if tx_index >= leaf_level.len() {
            return Err(BridgeError::IndexOutOfRange {
                name: "leaf tx_index",
                index: tx_index,
                max: leaf_level.len(),
            });
        }
        let output_index = (slot % params.fanout_branching) * params.lamport_chunks_per_slot + chunk;
        let txid = leaf_level[tx_index].compute_txid();
        Ok(OutPoint::new(txid, output_index as u32))
    }

    /// Returns cloned txs from root down to the leaf containing `slot`.
    pub fn path_to_slot(&self, params: &Params, slot: usize) -> Result<Vec<Transaction>, BridgeError> {
        if slot >= params.deposit_count {
            return Err(BridgeError::IndexOutOfRange {
                name: "slot",
                index: slot,
                max: params.deposit_count,
            });
        }
        let depth = self.levels.len();
        let leaf_tx_index = slot / params.fanout_branching;

        // Compute node index at each level (leaf to root)
        let mut indices = vec![0usize; depth];
        indices[depth - 1] = leaf_tx_index;
        for d in (0..depth - 1).rev() {
            indices[d] = indices[d + 1] / params.fanout_branching;
        }

        Ok(indices
            .iter()
            .enumerate()
            .map(|(level, &idx)| self.levels[level][idx].clone())
            .collect())
    }

    /// Returns the prevouts needed to sign/verify a kickoff transaction for a given slot.
    pub fn kickoff_prevouts(&self, params: &Params, slot: usize) -> Result<Vec<TxOut>, BridgeError> {
        if slot >= params.deposit_count {
            return Err(BridgeError::IndexOutOfRange {
                name: "slot",
                index: slot,
                max: params.deposit_count,
            });
        }
        let leaf_level = &self.levels[self.levels.len() - 1];
        let tx_index = slot / params.fanout_branching;
        if tx_index >= leaf_level.len() {
            return Err(BridgeError::IndexOutOfRange {
                name: "leaf tx_index",
                index: tx_index,
                max: leaf_level.len(),
            });
        }
        Ok((0..params.lamport_chunks_per_slot)
            .map(|chunk| {
                let output_index = (slot % params.fanout_branching) * params.lamport_chunks_per_slot + chunk;
                leaf_level[tx_index].output[output_index].clone()
            })
            .collect())
    }
}
