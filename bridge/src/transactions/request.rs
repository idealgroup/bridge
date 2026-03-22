use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{ScriptBuf, Witness};

use crate::actor::{Committee, Depositor};
use crate::params::Params;
use crate::scripts;
use crate::BridgeError;

/// Builds a request transaction.
///
/// - Input: depositor's `request_utxo` (signed by depositor at broadcast time)
/// - Output: `DEPOSIT_SIZE` locked in P2TR (committee key-spend + cancel script leaf)
pub fn build_request_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    depositor: &Depositor,
    committee: &Committee,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    let spend_info = scripts::request_spend_info(
        secp,
        committee.pubkey,
        depositor.pubkey,
        depositor.deposit_secret_hash(),
        params.deposit_timeout,
    )?;

    let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: depositor.request_utxo,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: params.deposit_size,
            script_pubkey,
        }],
    })
}

/// Signs the request transaction (depositor key-spend, no script tree on input UTXO).
pub fn sign_request_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    depositor_keypair: &Keypair,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let tweaked = depositor_keypair.tap_tweak(secp, None);
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
    use crate::actor::{Committee, Depositor};
    use crate::params::Params;
    use bitcoin::{Address, Network, OutPoint, Txid};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_request_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let depositor = Depositor::new(
            &mut rng,
            &secp,
            0,
            OutPoint::new(Txid::all_zeros(), 0),
        );
        let committee = Committee::new(&mut rng, &secp);

        let tx = build_request_tx(&secp, &depositor, &committee, &params).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }

    #[test]
    fn test_sign_request_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use crate::network::BITCOIN_NETWORK;
        let mut depositor = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0));
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.deposit_size).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        let mut tx = build_request_tx(&secp, &depositor, &committee, &params).unwrap();
        let prevouts = [TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, depositor.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        }];
        sign_request_tx(&secp, &mut tx, &depositor.keypair, &prevouts).unwrap();

        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness[0].len(), 64);

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }
}
