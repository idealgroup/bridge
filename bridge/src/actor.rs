use std::collections::HashMap;

use bitcoin::key::{Keypair, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::{Address, Network, OutPoint, Txid};
use bitcoin::hashes::{sha256, Hash};
use rand::{CryptoRng, Rng};

use crate::engine::{BitVMEngine, DisproveSecret};
use crate::params::Params;
use crate::scripts;
use crate::transactions::{cancel, deposit, disprove, fanout, kickoff, request, withdraw};
use crate::BridgeError;

pub struct Operator {
    pub keypair: Keypair,
    pub pubkey: XOnlyPublicKey,
    pub init_utxo: OutPoint,
    pub lamport_keys: Vec<Box<lamport::SecretKey>>,
    pub fanout_tree: Option<fanout::FanoutTree>,
    /// Presigned withdrawTxs (committee-signed input 0), keyed by kickoff txid.
    pub presigned_withdraws: HashMap<Txid, Transaction>,
}

pub struct Depositor {
    pub keypair: Keypair,
    pub pubkey: XOnlyPublicKey,
    pub index: usize,
    pub request_utxo: OutPoint,
    pub deposit_secret: [u8; 32],
}

pub struct Committee {
    pub keypair: Keypair,
    pub pubkey: XOnlyPublicKey,
}

fn random_keypair(
    rng: &mut (impl CryptoRng + Rng),
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Keypair {
    let mut secret_bytes = [0u8; 32];
    loop {
        rng.fill(&mut secret_bytes);
        if let Ok(sk) = SecretKey::from_slice(&secret_bytes) {
            return Keypair::from_secret_key(secp, &sk);
        }
    }
}

impl Operator {
    pub fn new(
        rng: &mut (impl CryptoRng + Rng),
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        init_utxo: OutPoint,
        deposit_count: usize,
    ) -> Self {
        let keypair = random_keypair(rng, secp);
        let (pubkey, _) = keypair.x_only_public_key();
        let lamport_keys = (0..deposit_count)
            .map(|_| lamport::SecretKey::random(rng))
            .collect();
        Self {
            keypair,
            pubkey,
            init_utxo,
            lamport_keys,
            fanout_tree: None,
            presigned_withdraws: HashMap::new(),
        }
    }

    pub fn lamport_pubkey(&self, slot: usize) -> Result<Box<lamport::PublicKey>, BridgeError> {
        self.lamport_keys
            .get(slot)
            .map(|sk| sk.public_key())
            .ok_or(BridgeError::IndexOutOfRange {
                name: "lamport slot",
                index: slot,
                max: self.lamport_keys.len(),
            })
    }

    /// Build and sign the full fanout tree, storing it internally.
    pub fn create_fanout_tree(
        &mut self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        init_txout: &TxOut,
        params: &Params,
    ) -> Result<(), BridgeError> {
        let mut tree = fanout::build_fanout_tree(secp, self, params)?;
        fanout::sign_fanout_tree(secp, &mut tree, &self.keypair, init_txout, params)?;
        self.fanout_tree = Some(tree);
        Ok(())
    }

    /// Compute the kickoff txid for a given slot without signing.
    /// Requires the fanout tree to be set (built or built+signed — doesn't matter,
    /// txids are witness-stripped).
    pub fn kickoff_txid(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        slot: usize,
        disprove_secret_hash: [u8; 32],
        params: &Params,
    ) -> Result<Txid, BridgeError> {
        let tree = self
            .fanout_tree
            .as_ref()
            .ok_or(BridgeError::MissingData("fanout_tree"))?;
        let tx = kickoff::build_kickoff_tx(secp, self, slot, tree, disprove_secret_hash, params)?;
        Ok(tx.compute_txid())
    }

    /// Build and sign a kickoffTx for a deposit slot.
    pub fn create_kickoff(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        slot: usize,
        disprove_secret_hash: [u8; 32],
        proof_msg: &[u8; lamport::MSG_LEN],
        params: &Params,
    ) -> Result<Transaction, BridgeError> {
        let tree = self
            .fanout_tree
            .as_ref()
            .ok_or(BridgeError::MissingData("fanout_tree"))?;
        let mut tx =
            kickoff::build_kickoff_tx(secp, self, slot, tree, disprove_secret_hash, params)?;
        let prevouts = tree.kickoff_prevouts(params, slot)?;
        let lamport_sig = self.lamport_keys
            .get(slot)
            .ok_or(BridgeError::IndexOutOfRange {
                name: "lamport slot",
                index: slot,
                max: self.lamport_keys.len(),
            })?
            .sign(proof_msg);
        let lamport_pk = self.lamport_pubkey(slot)?;
        kickoff::sign_kickoff_tx(
            secp,
            &mut tx,
            &self.keypair,
            &lamport_sig,
            &lamport_pk,
            &prevouts,
            params,
        )?;
        Ok(tx)
    }

    /// Store a presigned withdrawTx (committee-signed input 0).
    /// Indexes by kickoff txid read from input[1].
    pub fn receive_presigned_withdraw(
        &mut self,
        tx: Transaction,
    ) -> Result<(), BridgeError> {
        let kickoff_txid = tx.input.get(1)
            .ok_or(BridgeError::MissingData("withdraw tx input[1]"))?
            .previous_output
            .txid;
        self.presigned_withdraws.insert(kickoff_txid, tx);
        Ok(())
    }

    /// Sign withdraw input 1 (connector key-spend) on a stored presigned withdraw tx.
    pub fn complete_withdraw(
        &mut self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        kickoff_txid: Txid,
        disprove_secret_hash: [u8; 32],
        withdraw_prevouts: &[TxOut],
    ) -> Result<Transaction, BridgeError> {
        let mut tx = self
            .presigned_withdraws
            .get(&kickoff_txid)
            .ok_or(BridgeError::MissingData("presigned_withdraw"))?
            .clone();
        let connector_info =
            scripts::connector_spend_info(secp, self.pubkey, disprove_secret_hash)?;
        withdraw::sign_withdraw_input1(
            secp,
            &mut tx,
            &self.keypair,
            &connector_info,
            withdraw_prevouts,
        )?;
        self.presigned_withdraws.insert(kickoff_txid, tx.clone());
        Ok(tx)
    }
}

impl Depositor {
    pub fn new(
        rng: &mut (impl CryptoRng + Rng),
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        index: usize,
        request_utxo: OutPoint,
    ) -> Self {
        let keypair = random_keypair(rng, secp);
        let (pubkey, _) = keypair.x_only_public_key();
        let mut deposit_secret = [0u8; 32];
        rng.fill(&mut deposit_secret);
        Self {
            keypair,
            pubkey,
            index,
            request_utxo,
            deposit_secret,
        }
    }

    pub fn deposit_secret_hash(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.deposit_secret).to_byte_array()
    }

    /// Build and sign a requestTx.
    pub fn create_request(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        committee_pubkey: XOnlyPublicKey,
        params: &Params,
    ) -> Result<Transaction, BridgeError> {
        let mut tx = request::build_request_tx(secp, self, committee_pubkey, params)?;
        let prevout = TxOut {
            value: params.request_input_value(),
            script_pubkey: Address::p2tr(secp, self.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        request::sign_request_tx(secp, &mut tx, &self.keypair, &[prevout])?;
        Ok(tx)
    }

    /// Build and sign a cancelTx (escape hatch).
    pub fn create_cancel(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        committee_pubkey: XOnlyPublicKey,
        request_txid: Txid,
        request_prevout: &TxOut,
        params: &Params,
    ) -> Result<Transaction, BridgeError> {
        let request_spend_info = scripts::request_spend_info(
            secp,
            committee_pubkey,
            self.pubkey,
            self.deposit_secret_hash(),
            params.deposit_timeout,
        )?;
        let mut tx = cancel::build_cancel_tx(secp, self, request_txid, params)?;
        let prevouts = [request_prevout.clone()];
        cancel::sign_cancel_tx(
            secp,
            &mut tx,
            &self.keypair,
            &self.deposit_secret,
            &request_spend_info,
            self.pubkey,
            self.deposit_secret_hash(),
            params.deposit_timeout,
            &prevouts,
        )?;
        Ok(tx)
    }

}

impl Committee {
    pub fn new(
        rng: &mut (impl CryptoRng + Rng),
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Self {
        let keypair = random_keypair(rng, secp);
        let (pubkey, _) = keypair.x_only_public_key();
        Self { keypair, pubkey }
    }

    /// Presign a depositTx (key-spend on request output).
    pub fn presign_deposit(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        request_txid: Txid,
        depositor: &Depositor,
        request_prevout: &TxOut,
        params: &Params,
    ) -> Result<Transaction, BridgeError> {
        let request_spend_info = scripts::request_spend_info(
            secp,
            self.pubkey,
            depositor.pubkey,
            depositor.deposit_secret_hash(),
            params.deposit_timeout,
        )?;
        let mut tx = deposit::build_deposit_tx(secp, request_txid, self, params)?;
        let prevouts = [request_prevout.clone()];
        deposit::presign_deposit_tx(
            secp,
            &mut tx,
            &self.keypair,
            &request_spend_info,
            &prevouts,
        )?;
        Ok(tx)
    }

    /// Presign withdrawTx input 0 (key-spend on deposit output).
    pub fn presign_withdraw(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        deposit_txid: Txid,
        kickoff_txid: Txid,
        operator: &Operator,
        withdraw_prevouts: &[TxOut],
        params: &Params,
    ) -> Result<Transaction, BridgeError> {
        let mut tx =
            withdraw::build_withdraw_tx(secp, deposit_txid, kickoff_txid, operator, params)?;
        withdraw::presign_withdraw_input0(
            secp,
            &mut tx,
            &self.keypair,
            withdraw_prevouts,
        )?;
        Ok(tx)
    }
}

#[derive(Default)]
pub struct Challenger;

impl Challenger {
    pub fn new() -> Self {
        Challenger
    }

    /// Verify a proof using the engine; returns the disprove secret if the proof is invalid.
    pub fn check_proof(
        &self,
        engine: &impl BitVMEngine,
        proof: &crate::engine::Proof,
        lamport_pk: &lamport::PublicKey,
    ) -> Result<Option<DisproveSecret>, BridgeError> {
        engine.extract_disprove_secret(proof, lamport_pk)
    }

    /// Build a fully-witnessed disproveTx.
    pub fn create_disprove(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        kickoff_txid: Txid,
        disprove_secret: DisproveSecret,
        disprove_secret_hash: [u8; 32],
        operator_pubkey: XOnlyPublicKey,
    ) -> Result<Transaction, BridgeError> {
        let connector_info =
            scripts::connector_spend_info(secp, operator_pubkey, disprove_secret_hash)?;
        let mut tx = disprove::build_disprove_tx(kickoff_txid);
        disprove::witness_disprove_tx(
            &mut tx,
            disprove_secret,
            disprove_secret_hash,
            &connector_info,
        )?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};

    use crate::engine::MockEngine;
    use crate::network::BITCOIN_NETWORK;
    use crate::test_support::{test_rng, dummy_outpoint};

    #[test]
    fn test_operator_creation() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let op = Operator::new(&mut rng, &secp, dummy_outpoint(), 4);
        assert_eq!(op.lamport_keys.len(), 4);
        assert!(op.fanout_tree.is_none());
        assert!(op.presigned_withdraws.is_empty());
    }

    #[test]
    fn test_depositor_secret_hash() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let dep = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
        let hash = dep.deposit_secret_hash();
        assert_eq!(hash.len(), 32);
        // Deterministic
        let mut rng2 = test_rng();
        let dep2 = Depositor::new(&mut rng2, &secp, 0, dummy_outpoint());
        assert_eq!(dep.deposit_secret_hash(), dep2.deposit_secret_hash());
    }

    #[test]
    fn test_committee_creation() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let c = Committee::new(&mut rng, &secp);
        assert_ne!(c.pubkey.serialize(), [0u8; 32]);
    }

    // --- Actor-level flow tests ---

    #[test]
    fn test_depositor_create_request_and_committee_presign_deposit() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let mut rng = test_rng();

        let mut depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
        depositor.request_utxo =
            BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        // Depositor creates request
        let request_tx = depositor.create_request(&secp, committee.pubkey, &params).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
        let request_txid = request_tx.compute_txid();

        // Committee presigns deposit
        let deposit_tx = committee
            .presign_deposit(
                &secp,
                request_txid,
                &depositor,
                &request_tx.output[0],
                &params,
            )
            .unwrap();

        BITCOIN_NETWORK.broadcast_tx(&deposit_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_depositor_create_cancel() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let mut rng = test_rng();

        let mut depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
        depositor.request_utxo =
            BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        let request_tx = depositor.create_request(&secp, committee.pubkey, &params).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(params.deposit_timeout.to_consensus_u32() as u64 + 1).unwrap();
        let request_txid = request_tx.compute_txid();

        let cancel_tx = depositor
            .create_cancel(
                &secp,
                committee.pubkey,
                request_txid,
                &request_tx.output[0],
                &params,
            )
            .unwrap();

        BITCOIN_NETWORK.broadcast_tx(&cancel_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_operator_create_fanout_and_kickoff() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let mut rng = test_rng();

        let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
        operator.init_utxo =
            BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };

        operator
            .create_fanout_tree(&secp, &init_txout, &params)
            .unwrap();
        assert!(operator.fanout_tree.is_some());

        // Confirm fanout tree
        for level in &operator.fanout_tree.as_ref().unwrap().levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let slot = 0;
        let disprove_hash = [0xaa; 32];
        let proof_msg = [0xbb; lamport::MSG_LEN];

        let kickoff_tx = operator
            .create_kickoff(&secp, slot, disprove_hash, &proof_msg, &params)
            .unwrap();

        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_full_withdraw_flow() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let mut rng = test_rng();

        // 1. Setup depositor + committee
        let mut depositor = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
        depositor.request_utxo =
            BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        // 2. Request → deposit chain
        let request_tx = depositor.create_request(&secp, committee.pubkey, &params).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
        let request_txid = request_tx.compute_txid();

        let deposit_tx = committee
            .presign_deposit(&secp, request_txid, &depositor, &request_tx.output[0], &params)
            .unwrap();
        BITCOIN_NETWORK.broadcast_tx(&deposit_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
        let deposit_txid = deposit_tx.compute_txid();

        // 3. Operator builds fanout tree (builds + signs, stored internally)
        let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
        operator.init_utxo =
            BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        operator.create_fanout_tree(&secp, &init_txout, &params).unwrap();

        // 4. Committee presigns withdraw BEFORE kickoff is broadcast.
        //    This matches the real protocol: kickoff txid is deterministic
        //    (witness data doesn't affect txids), so committee can presign upfront.
        let slot = 0;
        let disprove_secret = [0xab; 20];
        let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();

        let kickoff_unsigned = kickoff::build_kickoff_tx(
            &secp, &operator, slot,
            operator.fanout_tree.as_ref().unwrap(),
            disprove_hash, &params,
        ).unwrap();
        let kickoff_txid = kickoff_unsigned.compute_txid();
        let kickoff_connector = kickoff_unsigned.output[0].clone();
        let withdraw_prevouts = vec![
            deposit_tx.output[0].clone(),
            kickoff_connector,
        ];
        let presigned_withdraw = committee
            .presign_withdraw(
                &secp,
                deposit_txid,
                kickoff_txid,
                &operator,
                &withdraw_prevouts,
                &params,
            )
            .unwrap();

        // 5. Hand presigned withdraw to operator
        operator
            .receive_presigned_withdraw(presigned_withdraw)
            .unwrap();

        // 6. Confirm fanout tree on-chain
        for level in &operator.fanout_tree.as_ref().unwrap().levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // 7. Operator creates and broadcasts kickoff
        let proof_msg = [0xbb; lamport::MSG_LEN];
        let kickoff_tx = operator
            .create_kickoff(&secp, slot, disprove_hash, &proof_msg, &params)
            .unwrap();
        assert_eq!(kickoff_tx.compute_txid(), kickoff_txid);
        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // 8. Wait for timeout
        BITCOIN_NETWORK.mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64).unwrap();

        // 9. Operator completes withdraw (signs input 1)
        let withdraw_tx = operator
            .complete_withdraw(&secp, kickoff_txid, disprove_hash, &withdraw_prevouts)
            .unwrap();

        // 10. Broadcast and confirm
        BITCOIN_NETWORK.broadcast_tx(&withdraw_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_challenger_disprove_flow() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let mut rng = test_rng();

        // Setup operator + fanout
        let mut operator = Operator::new(&mut rng, &secp, dummy_outpoint(), params.deposit_count);
        operator.init_utxo =
            BITCOIN_NETWORK.fund_p2tr(&secp, operator.pubkey, params.fanout_init_value()).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(&secp, operator.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        operator.create_fanout_tree(&secp, &init_txout, &params).unwrap();
        for level in &operator.fanout_tree.as_ref().unwrap().levels {
            for tx in level {
                BITCOIN_NETWORK.broadcast_tx(tx).unwrap();
            }
        }
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        // Challenger checks an invalid proof
        let challenger = Challenger::new();
        let engine = MockEngine;
        let mut invalid_proof = [0u8; 256];
        invalid_proof[0] = 0xFF; // invalid
        let lamport_pk = operator.lamport_pubkey(0).unwrap();
        let secret = challenger
            .check_proof(&engine, &invalid_proof, &lamport_pk)
            .unwrap();
        assert!(secret.is_some());
        let disprove_secret = secret.unwrap();
        let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();

        // Build kickoff (operator posts invalid proof)
        let slot = 0;
        let proof_msg = [0xbb; lamport::MSG_LEN];
        let kickoff_tx = operator
            .create_kickoff(&secp, slot, disprove_hash, &proof_msg, &params)
            .unwrap();
        BITCOIN_NETWORK.broadcast_tx(&kickoff_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
        let kickoff_txid = kickoff_tx.compute_txid();

        // Challenger builds disprove tx
        let disprove_tx = challenger
            .create_disprove(
                &secp,
                kickoff_txid,
                disprove_secret,
                disprove_hash,
                operator.pubkey,
            )
            .unwrap();

        BITCOIN_NETWORK.broadcast_tx(&disprove_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_challenger_valid_proof_no_secret() {
        let challenger = Challenger::new();
        let engine = MockEngine;
        let valid_proof = [0u8; 256]; // proof[0] == 0x00 → valid
        let mut rng = test_rng();
        let sk = lamport::SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let result = challenger.check_proof(&engine, &valid_proof, &pk).unwrap();
        assert!(result.is_none());
    }
}
