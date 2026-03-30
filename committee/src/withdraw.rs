use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Network, ScriptBuf, Txid, Witness};

use bridge::params::Params;
use bridge::BridgeError;

/// Builds a withdraw transaction.
///
/// - Input 0: depositTx.out[0], key-spend presigned by committee (SIGHASH_NONE)
/// - Input 1: kickoffTx.out[0] (connector), key-spend by operator (SIGHASH_ALL)
/// - Output 0: DEPOSIT_SIZE to operator
pub fn build_withdraw_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    deposit_txid: Txid,
    kickoff_txid: Txid,
    operator_pubkey: XOnlyPublicKey,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    let operator_address = Address::p2tr(secp, operator_pubkey, None, Network::Bitcoin);

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            // Input 0: deposit output (committee presigns)
            TxIn {
                previous_output: bitcoin::OutPoint::new(deposit_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            // Input 1: connector output (operator key-spend, nSequence enforces timelock)
            TxIn {
                previous_output: bitcoin::OutPoint::new(kickoff_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: params.kickoff_timeout,
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: params.deposit_size,
                script_pubkey: operator_address.script_pubkey(),
            },
        ],
    })
}

/// Committee presigns withdraw input 0 (key-spend on deposit output, no script tree).
pub fn presign_withdraw_input0(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    committee_keypair: &Keypair,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let tweaked = committee_keypair.tap_tweak(secp, None);
    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), TapSighashType::None)
        .map_err(BridgeError::Sighash)?;
    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
    tx.input[0].witness = Witness::p2tr_key_spend(&bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::None,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge::actor::Operator;
    use bridge::test_support::test_rng;
    use bitcoin::hashes::Hash;
    use bitcoin::OutPoint;

    #[test]
    fn test_build_withdraw_tx() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng, &secp,
            OutPoint::new(Txid::all_zeros(), 0),
            params.deposit_count,
        );

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();

        let tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, operator.pubkey, &params,
        ).unwrap();

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.input[1].sequence, params.kickoff_timeout);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }
}
