use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{ScriptBuf, Txid, Witness};

use bridge::params::Params;
use bridge::BridgeError;

/// Builds a deposit transaction.
///
/// - Input: requestTx.out[0], key-spend by committee (presigned, fee set at presign time)
/// - Output 0: DEPOSIT_SIZE, P2TR key-spend by committee
pub fn build_deposit_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    request_txid: Txid,
    committee_pubkey: XOnlyPublicKey,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::new(request_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: params.deposit_size,
            script_pubkey: ScriptBuf::new_p2tr(secp, committee_pubkey, None),
        }],
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
    use bridge::actor::Committee;
    use bitcoin::hashes::Hash;
    use rand::SeedableRng;

    #[test]
    fn test_build_deposit_tx() {
        let secp = Secp256k1::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let committee = Committee::new(&mut rng, &secp);

        let request_txid = Txid::all_zeros();
        let tx = build_deposit_tx(&secp, request_txid, committee.pubkey, &params).unwrap();

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }
}
