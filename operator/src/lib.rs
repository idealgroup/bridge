pub mod fanout;
pub mod kickoff;
pub mod withdraw;

use std::collections::HashMap;

use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::Txid;

use bridge::actor::Operator;
use bridge::network::BitcoinNetwork;
use bridge::params::Params;
use bridge::scripts;
use crate::fanout::FanoutTree;
use bridge::BridgeError;

pub struct OperatorClient {
    pub operator: Operator,
    pub params: Params,
    secp: Secp256k1<All>,
    fanout_tree: Option<FanoutTree>,
    /// Presigned withdrawTxs (committee-signed input 0), keyed by kickoff txid.
    presigned_withdraws: HashMap<Txid, Transaction>,
}

impl OperatorClient {
    pub fn new(operator: Operator, params: Params) -> Self {
        Self {
            operator,
            params,
            secp: Secp256k1::new(),
            fanout_tree: None,
            presigned_withdraws: HashMap::new(),
        }
    }

    /// Ensure the fanout tree is built and signed. No-op if already present.
    fn ensure_fanout_tree(&mut self) -> Result<(), BridgeError> {
        if self.fanout_tree.is_none() {
            let init_txout = TxOut {
                value: self.params.fanout_init_value(),
                script_pubkey: ScriptBuf::new_p2tr(
                    &self.secp,
                    self.operator.pubkey,
                    None,
                ),
            };
            let mut tree =
                fanout::build_fanout_tree(&self.secp, &self.operator, &self.params)?;
            fanout::sign_fanout_tree(
                &self.secp,
                &mut tree,
                &self.operator.keypair,
                &init_txout,
                &self.params,
            )?;
            self.fanout_tree = Some(tree);
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
        let tree = self
            .fanout_tree
            .as_ref()
            .ok_or(BridgeError::MissingData("fanout_tree"))?;
        let tx = kickoff::build_kickoff_tx(
            &self.secp,
            &self.operator,
            slot,
            tree,
            disprove_secret_hash,
            &self.params,
        )?;
        Ok(tx.compute_txid())
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
            .fanout_tree
            .as_ref()
            .ok_or(BridgeError::MissingData("fanout_tree"))?;
        let mut txs = tree.path_to_slot(&self.params, slot)?;

        let mut tx = kickoff::build_kickoff_tx(
            &self.secp,
            &self.operator,
            slot,
            tree,
            disprove_secret_hash,
            &self.params,
        )?;
        let prevouts = tree.kickoff_prevouts(&self.params, slot)?;
        let lamport_sig = self
            .operator
            .lamport_keys
            .get(slot)
            .ok_or(BridgeError::IndexOutOfRange {
                name: "lamport slot",
                index: slot,
                max: self.operator.lamport_keys.len(),
            })?
            .sign(proof);
        let lamport_pk = self.operator.lamport_pubkey(slot)?;
        kickoff::sign_kickoff_tx(
            &self.secp,
            &mut tx,
            &self.operator.keypair,
            &lamport_sig,
            &lamport_pk,
            &prevouts,
            &self.params,
        )?;
        txs.push(tx);
        Ok(txs)
    }

    /// Store a committee-signed withdraw tx. Indexes by kickoff txid from input[1].
    pub fn receive_presigned_withdraw(
        &mut self,
        tx: Transaction,
    ) -> Result<(), BridgeError> {
        let kickoff_txid = tx
            .input
            .get(1)
            .ok_or(BridgeError::MissingData("withdraw tx input[1]"))?
            .previous_output
            .txid;
        self.presigned_withdraws.insert(kickoff_txid, tx);
        Ok(())
    }

    /// Sign input 1 of a stored presigned withdraw tx and broadcast.
    pub fn complete_withdraw(
        &mut self,
        kickoff_txid: Txid,
        disprove_secret_hash: [u8; 32],
        withdraw_prevouts: &[TxOut],
        network: &BitcoinNetwork,
    ) -> Result<Transaction, BridgeError> {
        let mut tx = self
            .presigned_withdraws
            .get(&kickoff_txid)
            .ok_or(BridgeError::MissingData("presigned_withdraw"))?
            .clone();
        let connector_info = scripts::connector_spend_info(
            &self.secp,
            self.operator.pubkey,
            disprove_secret_hash,
        )?;
        withdraw::sign_withdraw_input1(
            &self.secp,
            &mut tx,
            &self.operator.keypair,
            &connector_info,
            withdraw_prevouts,
        )?;
        self.presigned_withdraws.insert(kickoff_txid, tx.clone());
        network.broadcast_tx(&tx)?;
        Ok(tx)
    }
}
