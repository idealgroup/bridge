use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::{Address, Network, Txid};

use bridge::actor::Operator;
use bridge::network::BitcoinNetwork;
use bridge::params::Params;
use bridge::BridgeError;

pub struct OperatorClient {
    pub operator: Operator,
    pub params: Params,
    secp: Secp256k1<All>,
}

impl OperatorClient {
    pub fn new(operator: Operator, params: Params) -> Self {
        Self {
            operator,
            params,
            secp: Secp256k1::new(),
        }
    }

    /// Ensure the fanout tree is built and signed. No-op if already present.
    fn ensure_fanout_tree(&mut self) -> Result<(), BridgeError> {
        if self.operator.fanout_tree.is_none() {
            let init_txout = TxOut {
                value: self.params.fanout_init_value(),
                script_pubkey: Address::p2tr(
                    &self.secp,
                    self.operator.pubkey,
                    None,
                    Network::Bitcoin,
                )
                .script_pubkey(),
            };
            self.operator
                .create_fanout_tree(&self.secp, &init_txout, &self.params)?;
        }
        Ok(())
    }

    /// Build and sign the full fanout tree (does not broadcast). No-op if already present.
    pub fn create_fanout_tree(&mut self) -> Result<(), BridgeError> {
        self.ensure_fanout_tree()
    }

    /// Compute the deterministic kickoff txid for a given slot.
    /// Lazily builds the fanout tree if not already present.
    pub fn kickoff_txid(
        &mut self,
        slot: usize,
        disprove_secret_hash: [u8; 32],
    ) -> Result<Txid, BridgeError> {
        self.ensure_fanout_tree()?;
        self.operator
            .kickoff_txid(&self.secp, slot, disprove_secret_hash, &self.params)
    }

    /// Build and sign a kickoff tx for a deposit slot.
    /// Lazily builds the fanout tree if not already present.
    ///
    /// Returns the fanout path txs (root to leaf) followed by the kickoff tx.
    /// Caller should broadcast all in order and then mine.
    pub fn create_kickoff(
        &mut self,
        slot: usize,
        disprove_secret_hash: [u8; 32],
        proof: &[u8; lamport::MSG_LEN],
    ) -> Result<Vec<Transaction>, BridgeError> {
        self.ensure_fanout_tree()?;
        let tree = self
            .operator
            .fanout_tree
            .as_ref()
            .ok_or(BridgeError::MissingData("fanout_tree"))?;
        let mut txs = tree.path_to_slot(&self.params, slot)?;
        let kickoff = self
            .operator
            .create_kickoff(&self.secp, slot, disprove_secret_hash, proof, &self.params)?;
        txs.push(kickoff);
        Ok(txs)
    }

    /// Store a committee-signed withdraw tx. Indexes by kickoff txid from input[1].
    pub fn receive_presigned_withdraw(
        &mut self,
        tx: Transaction,
    ) -> Result<(), BridgeError> {
        self.operator.receive_presigned_withdraw(tx)
    }

    /// Sign input 1 of a stored presigned withdraw tx and broadcast.
    pub fn complete_withdraw(
        &mut self,
        kickoff_txid: Txid,
        disprove_secret_hash: [u8; 32],
        withdraw_prevouts: &[TxOut],
        network: &BitcoinNetwork,
    ) -> Result<Transaction, BridgeError> {
        let tx = self.operator.complete_withdraw(
            &self.secp,
            kickoff_txid,
            disprove_secret_hash,
            withdraw_prevouts,
        )?;
        network.broadcast_tx(&tx)?;
        Ok(tx)
    }
}
