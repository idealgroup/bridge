use bitcoin::absolute::LockTime;
use bitcoin::blockdata::transaction::Sequence;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{ScriptBuf, Txid, Witness};

use bridge::actor::Depositor;
use bridge::params::Params;
use bridge::scripts;
use bridge::BridgeError;

/// Builds a cancel transaction.
///
/// - Input: requestTx.out[0], script-path (depositor sig + deposit_secret + CSV)
/// - Output: DEPOSIT_SIZE to depositor (P2TR key-spend)
pub fn build_cancel_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    depositor: &Depositor,
    request_txid: Txid,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::new(request_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: params.deposit_timeout, // required for OP_CSV
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: params.deposit_size,
            script_pubkey: ScriptBuf::new_p2tr(secp, depositor.pubkey, None),
        }],
    })
}

/// Signs the cancel transaction (depositor script-path on request output).
#[allow(clippy::too_many_arguments)]
pub fn sign_cancel_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    depositor_keypair: &Keypair,
    deposit_secret: &[u8; 32],
    request_spend_info: &TaprootSpendInfo,
    depositor_pubkey: XOnlyPublicKey,
    deposit_secret_hash: [u8; 32],
    deposit_timeout: Sequence,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let leaf_script = scripts::cancel_script(depositor_pubkey, deposit_secret_hash, deposit_timeout);
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

    let control_block = request_spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .ok_or(BridgeError::Signing("cancel leaf not in taproot tree".into()))?;

    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default,
        )
        .map_err(BridgeError::Sighash)?;

    let msg = Message::from_digest(*sighash.as_byte_array());
    // Script-path: sign with untweaked keypair
    let sig = secp.sign_schnorr_no_aux_rand(&msg, depositor_keypair);

    let sig_bytes = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };
    let mut witness = Witness::new();
    witness.push(sig_bytes.to_vec());
    witness.push(deposit_secret);
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[0].witness = witness;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge::actor::Committee;
    use bridge::test_support::BITCOIN_NETWORK;
    use bitcoin::OutPoint;
    use bitcoin::hashes::Hash;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_cancel_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let depositor = Depositor::new(
            &mut rng,
            &secp,
            0,
            OutPoint::new(Txid::all_zeros(), 0),
            [0xaa; 20],
        );

        let request_txid = Txid::all_zeros();
        let tx = build_cancel_tx(&secp, &depositor, request_txid, &params).unwrap();

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].sequence, params.deposit_timeout);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }

    #[test]
    fn test_sign_cancel_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        let mut depositor = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0), [0xaa; 20]);
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        // Build and sign request_tx (parent)
        let mut request_tx = crate::request::build_request_tx(&secp, &depositor, committee.pubkey, &params).unwrap();
        let depositor_prevout = TxOut {
            value: params.request_input_value(),
            script_pubkey: ScriptBuf::new_p2tr(&secp, depositor.pubkey, None),
        };
        crate::request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(params.deposit_timeout.to_consensus_u32() as u64 + 1).unwrap();

        let request_spend_info = scripts::request_spend_info(
            &secp,
            committee.pubkey,
            depositor.pubkey,
            depositor.deposit_secret_hash(),
            params.deposit_timeout,
        ).unwrap();

        let request_txid = request_tx.compute_txid();
        let mut tx = build_cancel_tx(&secp, &depositor, request_txid, &params).unwrap();

        let prevouts = [request_tx.output[0].clone()];
        sign_cancel_tx(
            &secp, &mut tx, &depositor.keypair,
            &depositor.deposit_secret,
            &request_spend_info,
            depositor.pubkey,
            depositor.deposit_secret_hash(),
            params.deposit_timeout,
            &prevouts,
        ).unwrap();

        // Witness: sig + deposit_secret + script + control_block
        assert_eq!(tx.input[0].witness.len(), 4);
        assert_eq!(tx.input[0].witness[0].len(), 64);
        assert_eq!(tx.input[0].witness[1].len(), 32);

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }

    #[test]
    fn test_cancel_wrong_secret_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        let mut depositor = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0), [0xaa; 20]);
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        let mut request_tx = crate::request::build_request_tx(&secp, &depositor, committee.pubkey, &params).unwrap();
        let depositor_prevout = TxOut {
            value: params.request_input_value(),
            script_pubkey: ScriptBuf::new_p2tr(&secp, depositor.pubkey, None),
        };
        crate::request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(params.deposit_timeout.to_consensus_u32() as u64 + 1).unwrap();

        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();

        let request_txid = request_tx.compute_txid();
        let mut tx = build_cancel_tx(&secp, &depositor, request_txid, &params).unwrap();

        let prevouts = [request_tx.output[0].clone()];

        let wrong_secret = [0xff; 32];
        sign_cancel_tx(
            &secp, &mut tx, &depositor.keypair,
            &wrong_secret, &request_spend_info,
            depositor.pubkey, depositor.deposit_secret_hash(),
            params.deposit_timeout, &prevouts,
        ).unwrap();

        assert!(
            BITCOIN_NETWORK.broadcast_tx(&tx).is_err(),
            "wrong deposit secret should be rejected"
        );
    }

    #[test]
    fn test_cancel_csv_not_satisfied() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        let mut depositor = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0), [0xaa; 20]);
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        let mut request_tx = crate::request::build_request_tx(&secp, &depositor, committee.pubkey, &params).unwrap();
        let depositor_prevout = TxOut {
            value: params.request_input_value(),
            script_pubkey: ScriptBuf::new_p2tr(&secp, depositor.pubkey, None),
        };
        crate::request::sign_request_tx(&secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.broadcast_tx(&request_tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
        // Do NOT mine extra blocks — CSV should fail

        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();

        let request_txid = request_tx.compute_txid();
        let mut tx = build_cancel_tx(&secp, &depositor, request_txid, &params).unwrap();

        // Set sequence too low (< deposit_timeout = from_height(5))
        tx.input[0].sequence = Sequence::from_height(1);

        let prevouts = [request_tx.output[0].clone()];

        sign_cancel_tx(
            &secp, &mut tx, &depositor.keypair,
            &depositor.deposit_secret, &request_spend_info,
            depositor.pubkey, depositor.deposit_secret_hash(),
            params.deposit_timeout, &prevouts,
        ).unwrap();

        assert!(
            BITCOIN_NETWORK.broadcast_tx(&tx).is_err(),
            "CSV with insufficient sequence should be rejected"
        );
    }
}
