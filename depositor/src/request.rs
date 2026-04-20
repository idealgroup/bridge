use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::{Amount, OutPoint, ScriptBuf, Witness};

use bitcoin::key::UntweakedPublicKey as XOnlyPublicKey;

use bridge::params::Params;
use bridge::scripts;
use bridge::BridgeError;

/// Builds a request transaction.
///
/// - Input: depositor's `request_utxo` (signed by depositor at broadcast time)
/// - Output 0: `request_input_value()` locked in P2TR (committee key-spend + cancel script leaf)
/// - Output 1: OP_RETURN with 20-byte Ethereum recipient address
///
/// **Zero-fee requestTx.** Output 0 carries the full input value so the tx
/// has no explicit fee. This only propagates on the regtest node
/// (`minrelaytxfee=0`). A production deployment must add a second input to
/// pay the relay fee — see `Params::request_input_value` for details.
pub fn build_request_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    depositor_pubkey: XOnlyPublicKey,
    deposit_secret_hash: [u8; 32],
    request_utxo: OutPoint,
    committee_pubkey: XOnlyPublicKey,
    params: &Params,
    eth_address: &[u8; 20],
) -> Result<Transaction, BridgeError> {
    let spend_info = scripts::request_spend_info(
        secp,
        committee_pubkey,
        depositor_pubkey,
        deposit_secret_hash,
        params.deposit_timeout,
    )?;

    let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    // OP_RETURN output with 20-byte Ethereum address
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(eth_address)
        .into_script();

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: request_utxo,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: params.request_input_value(),
                script_pubkey,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            },
        ],
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
    use bridge::actor::{Committee, Depositor};
    use bridge::params::Params;
    use bitcoin::{Amount, Txid};
    use bitcoin::hashes::Hash;
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

        let tx = build_request_tx(&secp, depositor.pubkey, depositor.deposit_secret_hash(), depositor.request_utxo, committee.pubkey, &params, &[0xaa; 20]).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, params.request_input_value());
        assert_eq!(tx.output[1].value, Amount::ZERO);
        assert!(tx.output[1].script_pubkey.is_op_return());
    }

    #[test]
    fn test_sign_request_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        use bridge::test_support::BITCOIN_NETWORK;
        let mut depositor = Depositor::new(&mut rng, &secp, 0, OutPoint::new(Txid::all_zeros(), 0));
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(&secp, depositor.pubkey, params.request_input_value()).unwrap();
        let committee = Committee::new(&mut rng, &secp);

        let mut tx = build_request_tx(&secp, depositor.pubkey, depositor.deposit_secret_hash(), depositor.request_utxo, committee.pubkey, &params, &[0xaa; 20]).unwrap();
        let prevouts = [TxOut {
            value: params.request_input_value(),
            script_pubkey: ScriptBuf::new_p2tr(&secp, depositor.pubkey, None),
        }];
        sign_request_tx(&secp, &mut tx, &depositor.keypair, &prevouts).unwrap();

        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness[0].len(), 64);

        BITCOIN_NETWORK.broadcast_tx(&tx).unwrap();
        BITCOIN_NETWORK.mine_blocks(1).unwrap();
    }
}
