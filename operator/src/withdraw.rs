use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::Witness;

use bridge::BridgeError;

/// Operator signs withdraw input 1 (key-spend on connector).
///
/// The timelock is enforced by nSequence on this input, which the committee's
/// SIGHASH_NONE signature on input 0 still commits to (BIP 341: all input
/// sequences are covered regardless of sighash type).
pub fn sign_withdraw_input1(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    operator_keypair: &Keypair,
    connector_spend_info: &TaprootSpendInfo,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let merkle_root = connector_spend_info.merkle_root();
    let tweaked = operator_keypair.tap_tweak(secp, merkle_root);

    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            1, &Prevouts::All(prevouts), TapSighashType::Default,
        )
        .map_err(BridgeError::Sighash)?;

    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());

    tx.input[1].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    });
    Ok(())
}
