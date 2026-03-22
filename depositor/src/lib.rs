use bitcoin::key::UntweakedPublicKey as XOnlyPublicKey;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::{OutPoint, Txid};

use bridge::actor::Depositor;
use bridge::params::Params;
use bridge::BridgeError;

pub struct DepositorClient {
    pub depositor: Depositor,
    pub params: Params,
    secp: Secp256k1<All>,
}

impl DepositorClient {
    pub fn new(depositor: Depositor, params: Params) -> Self {
        Self {
            depositor,
            params,
            secp: Secp256k1::new(),
        }
    }

    /// Build and sign a requestTx. The caller provides the funded UTXO
    /// (must be a P2TR of the depositor's pubkey with `deposit_size` value).
    pub fn create_request(
        &mut self,
        committee_pubkey: XOnlyPublicKey,
        request_utxo: OutPoint,
    ) -> Result<Transaction, BridgeError> {
        self.depositor.request_utxo = request_utxo;
        self.depositor
            .create_request(&self.secp, committee_pubkey, &self.params)
    }

    /// Build and sign a cancelTx (escape hatch).
    pub fn create_cancel(
        &self,
        committee_pubkey: XOnlyPublicKey,
        request_txid: Txid,
        request_prevout: &TxOut,
    ) -> Result<Transaction, BridgeError> {
        self.depositor.create_cancel(
            &self.secp,
            committee_pubkey,
            request_txid,
            request_prevout,
            &self.params,
        )
    }

    /// Store a presigned depositTx from the committee.
    pub fn receive_presigned_deposit(&mut self, tx: Transaction) {
        self.depositor.receive_presigned_deposit(tx);
    }

    /// Store a presigned withdrawTx (committee-signed input 0) for a given operator.
    pub fn receive_presigned_withdraw(
        &mut self,
        operator_index: usize,
        tx: Transaction,
    ) -> Result<(), BridgeError> {
        self.depositor
            .receive_presigned_withdraw(operator_index, tx)
    }
}
