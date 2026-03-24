use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::Transaction;

use bridge::actor::Challenger;
use bridge::engine::BitVMEngine;
use bridge::params::Params;
use bridge::transactions::kickoff;
use bridge::BridgeError;

pub struct ChallengerClient<E: BitVMEngine> {
    challenger: Challenger,
    engine: E,
    params: Params,
    secp: Secp256k1<All>,
}

impl<E: BitVMEngine> ChallengerClient<E> {
    pub fn new(engine: E, params: Params) -> Self {
        Self {
            challenger: Challenger::new(),
            engine,
            params,
            secp: Secp256k1::new(),
        }
    }

    /// Examine a kickoff transaction and build a disprove tx if the proof is invalid.
    ///
    /// Returns `Some(disprove_tx)` if fraud detected, `None` if proof is valid.
    pub fn challenge_kickoff(
        &self,
        kickoff_tx: &Transaction,
    ) -> Result<Option<Transaction>, BridgeError> {
        let data = kickoff::extract_proof_from_kickoff(kickoff_tx, &self.params)?;

        let secret = self
            .challenger
            .check_proof(&self.engine, &data.proof, &data.lamport_pk)?;

        let Some(disprove_secret) = secret else {
            return Ok(None);
        };

        let disprove_hash =
            bitcoin::hashes::sha256::Hash::hash(&disprove_secret).to_byte_array();
        let kickoff_txid = kickoff_tx.compute_txid();

        let disprove_tx = self.challenger.create_disprove(
            &self.secp,
            kickoff_txid,
            disprove_secret,
            disprove_hash,
            data.operator_pubkey,
        )?;

        Ok(Some(disprove_tx))
    }

    /// Heuristic scan: returns candidate kickoff txs from a block.
    ///
    /// A kickoff tx has exactly `lamport_chunks_per_slot` inputs and 2 outputs.
    /// Candidates are then validated by `extract_proof_from_kickoff`.
    pub fn scan_block_for_kickoffs(&self, block: &bitcoin::Block) -> Vec<Transaction> {
        block
            .txdata
            .iter()
            .filter(|tx| {
                tx.input.len() == self.params.lamport_chunks_per_slot
                    && tx.output.len() == 2
            })
            .cloned()
            .collect()
    }
}
