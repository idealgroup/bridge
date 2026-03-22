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

    /// Build, sign, and broadcast the full fanout tree.
    pub fn create_fanout_tree(&mut self, network: &BitcoinNetwork) -> Result<(), BridgeError> {
        let init_txout = TxOut {
            value: self.params.fanout_init_value(),
            script_pubkey: Address::p2tr(&self.secp, self.operator.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        self.operator
            .create_fanout_tree(&self.secp, &init_txout, &self.params)?;
        let tree = self
            .operator
            .fanout_tree
            .as_ref()
            .ok_or(BridgeError::MissingData("fanout_tree"))?;
        for level in &tree.levels {
            for tx in level {
                network.broadcast_tx(tx)?;
            }
        }
        Ok(())
    }

    /// Compute the deterministic kickoff txid for a given slot.
    pub fn kickoff_txid(
        &self,
        slot: usize,
        disprove_secret_hash: [u8; 32],
    ) -> Result<Txid, BridgeError> {
        self.operator
            .kickoff_txid(&self.secp, slot, disprove_secret_hash, &self.params)
    }

    /// Build and sign a kickoff tx for a deposit slot.
    pub fn create_kickoff(
        &self,
        slot: usize,
        disprove_secret_hash: [u8; 32],
        proof: &[u8; lamport::MSG_LEN],
    ) -> Result<Transaction, BridgeError> {
        self.operator
            .create_kickoff(&self.secp, slot, disprove_secret_hash, proof, &self.params)
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
