use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Network, ScriptBuf, Txid, Witness};

use crate::actor::Committee;
use crate::params::Params;
use crate::scripts;
use crate::BridgeError;

/// Builds a deposit transaction.
///
/// - Input: requestTx.out[0], key-spend by committee (presigned)
/// - Output 0: DEPOSIT_SIZE, P2TR key-spend by committee
/// - Output 1: P2A anchor (240 sats)
pub fn build_deposit_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    request_txid: Txid,
    committee: &Committee,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    let committee_address = Address::p2tr(secp, committee.pubkey, None, Network::Bitcoin);

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::new(request_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: params.deposit_size,
                script_pubkey: committee_address.script_pubkey(),
            },
            // P2A anchor for CPFP fee bumping
            TxOut {
                value: scripts::P2A_DUST,
                script_pubkey: scripts::p2a_script(),
            },
        ],
    })
}

/// Committee presigns the deposit transaction (key-spend on request output with cancel script tree).
pub fn presign_deposit_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    committee_keypair: &Keypair,
    request_spend_info: &TaprootSpendInfo,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let tweaked = committee_keypair.tap_tweak(secp, request_spend_info.merkle_root());
    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(BridgeError::Sighash)?;
    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
    tx.input[0].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::Depositor;
    use crate::scripts;
    use bitcoin::OutPoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_deposit_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let committee = Committee::new(&mut rng, &secp);

        let request_txid = Txid::all_zeros();
        let tx = build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }

    #[test]
    fn test_presign_deposit_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::network::BITCOIN_NETWORK;
        use crate::transactions::request;

        let mut depositor = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0));
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        // Build and confirm request_tx (parent of deposit)
        let mut request_tx = request::build_request_tx(&secp, &depositor, committee.pubkey, &params).unwrap();
        let depositor_prevout = TxOut {
            value: params.request_input_value(),
            script_pubkey: bitcoin::Address::p2tr(&secp, depositor.pubkey, None, bitcoin::Network::Bitcoin)
                .script_pubkey(),
        };
        request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();

        let request_spend_info = scripts::request_spend_info(
            &secp,
            committee.pubkey,
            depositor.pubkey,
            depositor.deposit_secret_hash(),
            params.deposit_timeout,
        ).unwrap();

        let request_txid = request_tx.compute_txid();
        let mut tx = build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();

        let prevouts = [request_tx.output[0].clone()];
        presign_deposit_tx(
            &secp, &mut tx, &committee.keypair, &request_spend_info, &prevouts,
        ).unwrap();

        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness[0].len(), 64);

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }
}
