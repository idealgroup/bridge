use bitcoin::absolute::LockTime;
use bitcoin::blockdata::transaction::Sequence;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Amount, Network, ScriptBuf, Txid, Witness};

use crate::actor::Operator;
use crate::params::Params;
use crate::scripts;
use crate::BridgeError;

/// Builds a withdraw transaction.
///
/// - Input 0: depositTx.out[0], key-spend presigned by committee
/// - Input 1: kickoffTx.out[0] (connector), script-path operator sig + CSV
/// - Output 0: DEPOSIT_SIZE to operator
/// - Output 1: P2A anchor (0 sats)
pub fn build_withdraw_tx(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    deposit_txid: Txid,
    kickoff_txid: Txid,
    operator: &Operator,
    params: &Params,
) -> Result<Transaction, BridgeError> {
    let operator_address = Address::p2tr(secp, operator.pubkey, None, Network::Bitcoin);

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
            // Input 1: connector output (operator signs + CSV)
            TxIn {
                previous_output: bitcoin::OutPoint::new(kickoff_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: params.kickoff_timeout, // required for OP_CSV
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: params.deposit_size,
                script_pubkey: operator_address.script_pubkey(),
            },
            // P2A anchor
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(&[]),
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

/// Operator signs withdraw input 1 (script-path on connector with CSV).
pub fn sign_withdraw_input1(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tx: &mut Transaction,
    operator_keypair: &Keypair,
    connector_spend_info: &TaprootSpendInfo,
    operator_pubkey: XOnlyPublicKey,
    kickoff_timeout: Sequence,
    prevouts: &[TxOut],
) -> Result<(), BridgeError> {
    let leaf_script = scripts::withdraw_script(operator_pubkey, kickoff_timeout);
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

    let control_block = connector_spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .ok_or(BridgeError::Signing("withdraw leaf not in taproot tree".into()))?;

    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            1, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default,
        )
        .map_err(BridgeError::Sighash)?;

    let msg = Message::from_digest(*sighash.as_byte_array());
    // Script-path: sign with untweaked keypair
    let sig = secp.sign_schnorr_no_aux_rand(&msg, operator_keypair);

    let sig_bytes = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };
    let mut witness = Witness::new();
    witness.push(sig_bytes.to_vec());
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[1].witness = witness;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::Committee;
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::OutPoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_build_withdraw_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng,
            &secp,
            OutPoint::new(Txid::all_zeros(), 0),
            params.deposit_count,
        );

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();

        let tx = build_withdraw_tx(
            &secp,
            deposit_txid,
            kickoff_txid,
            &operator,
            &params,
        )
        .unwrap();

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.input[1].sequence, params.kickoff_timeout);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, params.deposit_size);
    }

    #[test]
    fn test_presign_withdraw_input0() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count,
        );
        let committee = Committee::new(&mut rng, &secp);

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        // Deposit output is committee P2TR key-spend (no script tree)
        let deposit_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, committee.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        // Connector output (placeholder for prevouts array)
        let disprove_hash = [0xaa; 20];
        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash, params.kickoff_timeout,
        ).unwrap();
        let connector_prevout = TxOut {
            value: params.dust_amount,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
        };

        let prevouts = [deposit_prevout, connector_prevout];
        presign_withdraw_input0(&secp, &mut tx, &committee.keypair, &prevouts).unwrap();

        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness[0].len(), 64);

        use crate::network::BITCOIN_NETWORK;
        BITCOIN_NETWORK.verify_input(&tx, 0, &prevouts).unwrap();
    }

    #[test]
    fn test_sign_withdraw_input1() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count,
        );
        let committee = Committee::new(&mut rng, &secp);

        let disprove_hash = hash160::Hash::hash(&[0xab; 20]).to_byte_array();
        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash, params.kickoff_timeout,
        ).unwrap();

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        let deposit_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, committee.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        let connector_prevout = TxOut {
            value: params.dust_amount,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
        };
        let prevouts = [deposit_prevout, connector_prevout];

        sign_withdraw_input1(
            &secp, &mut tx, &operator.keypair,
            &connector_info, operator.pubkey, params.kickoff_timeout, &prevouts,
        ).unwrap();

        // Witness: sig + script + control_block
        assert_eq!(tx.input[1].witness.len(), 3);
        assert_eq!(tx.input[1].witness[0].len(), 64);

        use crate::network::BITCOIN_NETWORK;
        BITCOIN_NETWORK.verify_input(&tx, 1, &prevouts).unwrap();
    }

    #[test]
    fn test_withdraw_input1_wrong_key_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count,
        );
        let committee = Committee::new(&mut rng, &secp);

        // Create a different operator (wrong signer)
        let wrong_operator = Operator::new(
            &mut rng, &secp, OutPoint::new(Txid::all_zeros(), 1), params.deposit_count,
        );

        let disprove_hash = hash160::Hash::hash(&[0xab; 20]).to_byte_array();
        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash, params.kickoff_timeout,
        ).unwrap();

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        let deposit_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, committee.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        let connector_prevout = TxOut {
            value: params.dust_amount,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
        };
        let prevouts = [deposit_prevout, connector_prevout];

        // Sign with wrong operator's key
        sign_withdraw_input1(
            &secp, &mut tx, &wrong_operator.keypair,
            &connector_info, operator.pubkey, params.kickoff_timeout, &prevouts,
        ).unwrap();

        use crate::network::BITCOIN_NETWORK;
        assert!(
            BITCOIN_NETWORK.verify_input(&tx, 1, &prevouts).is_err(),
            "wrong operator key should be rejected"
        );
    }

    #[test]
    fn test_withdraw_input1_csv_not_satisfied() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();
        let operator = Operator::new(
            &mut rng, &secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count,
        );
        let committee = Committee::new(&mut rng, &secp);

        let disprove_hash = hash160::Hash::hash(&[0xab; 20]).to_byte_array();
        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash, params.kickoff_timeout,
        ).unwrap();

        let deposit_txid = Txid::all_zeros();
        let kickoff_txid = Txid::all_zeros();
        let mut tx = build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        // Set sequence too low (< kickoff_timeout = from_height(10))
        tx.input[1].sequence = Sequence::from_height(1);

        let deposit_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(&secp, committee.pubkey, None, Network::Bitcoin)
                .script_pubkey(),
        };
        let connector_prevout = TxOut {
            value: params.dust_amount,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
        };
        let prevouts = [deposit_prevout, connector_prevout];

        sign_withdraw_input1(
            &secp, &mut tx, &operator.keypair,
            &connector_info, operator.pubkey, params.kickoff_timeout, &prevouts,
        ).unwrap();

        use crate::network::BITCOIN_NETWORK;
        assert!(
            BITCOIN_NETWORK.verify_input(&tx, 1, &prevouts).is_err(),
            "CSV with insufficient sequence should be rejected"
        );
    }
}
