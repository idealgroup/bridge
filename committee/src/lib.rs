pub mod deposit;
pub mod withdraw;

use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::Txid;

use bridge::actor::{Committee, Depositor};
use bridge::params::Params;
use bridge::scripts;
use bridge::BridgeError;

pub struct CommitteeClient {
    pub committee: Committee,
    pub params: Params,
    secp: Secp256k1<All>,
}

impl CommitteeClient {
    pub fn new(committee: Committee, params: Params) -> Self {
        Self {
            committee,
            params,
            secp: Secp256k1::new(),
        }
    }

    /// Presign a depositTx (key-spend on request output).
    pub fn presign_deposit(
        &self,
        request_txid: Txid,
        depositor: &Depositor,
        request_prevout: &TxOut,
    ) -> Result<Transaction, BridgeError> {
        let request_spend_info = scripts::request_spend_info(
            &self.secp,
            self.committee.pubkey,
            depositor.pubkey,
            depositor.deposit_secret_hash(),
            self.params.deposit_timeout,
        )?;
        let mut tx = deposit::build_deposit_tx(
            &self.secp,
            request_txid,
            self.committee.pubkey,
            &self.params,
        )?;
        let prevouts = [request_prevout.clone()];
        deposit::presign_deposit_tx(
            &self.secp,
            &mut tx,
            &self.committee.keypair,
            &request_spend_info,
            &prevouts,
        )?;
        Ok(tx)
    }

    /// Presign withdrawTx input 0 (key-spend on deposit output, SIGHASH_NONE).
    pub fn presign_withdraw(
        &self,
        deposit_txid: Txid,
        kickoff_txid: Txid,
        withdraw_prevouts: &[TxOut],
    ) -> Result<Transaction, BridgeError> {
        let mut tx = withdraw::build_withdraw_tx(
            deposit_txid,
            kickoff_txid,
            &self.params,
        )?;
        withdraw::presign_withdraw_input0(
            &self.secp,
            &mut tx,
            &self.committee.keypair,
            withdraw_prevouts,
        )?;
        Ok(tx)
    }
}
