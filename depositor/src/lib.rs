pub mod adjusted_sig;
pub mod request;
pub mod cancel;

use bitcoin::key::UntweakedPublicKey as XOnlyPublicKey;
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::{OutPoint, Txid};

use bridge::actor::Depositor;
use bridge::params::Params;
use bridge::scripts;
use bridge::BridgeError;

pub struct DepositorClient {
    pub depositor: Depositor,
    pub params: Params,
    /// 20-byte Ethereum address where wBTC will be minted (embedded in requestTx OP_RETURN).
    pub eth_address: [u8; 20],
    secp: Secp256k1<All>,
}

impl DepositorClient {
    pub fn new(depositor: Depositor, params: Params, eth_address: [u8; 20]) -> Self {
        Self {
            depositor,
            params,
            eth_address,
            secp: Secp256k1::new(),
        }
    }

    /// Build and sign a requestTx. The caller provides the funded UTXO
    /// (must be a P2TR of the depositor's pubkey with `request_input_value`).
    pub fn create_request(
        &mut self,
        committee_pubkey: XOnlyPublicKey,
        request_utxo: OutPoint,
    ) -> Result<Transaction, BridgeError> {
        self.depositor.request_utxo = request_utxo;
        let mut tx = request::build_request_tx(
            &self.secp,
            self.depositor.pubkey,
            self.depositor.deposit_secret_hash(),
            request_utxo,
            committee_pubkey,
            &self.params,
            &self.eth_address,
        )?;
        let prevout = TxOut {
            value: self.params.request_input_value(),
            script_pubkey: ScriptBuf::new_p2tr(&self.secp, self.depositor.pubkey, None),
        };
        request::sign_request_tx(&self.secp, &mut tx, &self.depositor.keypair, &[prevout])?;
        Ok(tx)
    }

    /// Build and sign a cancelTx (escape hatch).
    pub fn create_cancel(
        &self,
        committee_pubkey: XOnlyPublicKey,
        request_txid: Txid,
        request_prevout: &TxOut,
    ) -> Result<Transaction, BridgeError> {
        let request_spend_info = scripts::request_spend_info(
            &self.secp,
            committee_pubkey,
            self.depositor.pubkey,
            self.depositor.deposit_secret_hash(),
            self.params.deposit_timeout,
        )?;
        let mut tx = cancel::build_cancel_tx(
            &self.secp,
            &self.depositor,
            request_txid,
            &self.params,
        )?;
        let prevouts = [request_prevout.clone()];
        cancel::sign_cancel_tx(
            &self.secp,
            &mut tx,
            &self.depositor.keypair,
            &self.depositor.deposit_secret,
            &request_spend_info,
            self.depositor.pubkey,
            self.depositor.deposit_secret_hash(),
            self.params.deposit_timeout,
            &prevouts,
        )?;
        Ok(tx)
    }
}
