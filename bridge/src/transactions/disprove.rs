use bitcoin::absolute::LockTime;
use bitcoin::taproot::{LeafVersion, TaprootSpendInfo};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, ScriptBuf, Txid, Witness};

use crate::scripts;
use crate::BridgeError;

/// Builds an unsigned disprove transaction.
///
/// - Input: kickoffTx.out[0] (connector), script-path with hash preimage (no sig)
/// - Output: OP_RETURN (burns the connector)
pub fn build_disprove_tx(kickoff_txid: Txid) -> Transaction {
    let op_return = ScriptBuf::new_op_return(&[]);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::new(kickoff_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return,
        }],
    }
}

/// Attaches the script-path witness (hash preimage, no signature) to a disprove tx.
pub fn witness_disprove_tx(
    tx: &mut Transaction,
    disprove_secret: [u8; 20],
    disprove_secret_hash: [u8; 20],
    connector_spend_info: &TaprootSpendInfo,
) -> Result<(), BridgeError> {
    let leaf_script = scripts::disprove_script(disprove_secret_hash);
    let control_block = connector_spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .ok_or(BridgeError::Signing("disprove leaf not in taproot tree".into()))?;

    let mut witness = Witness::new();
    witness.push(disprove_secret);
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[0].witness = witness;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::key::{Keypair, UntweakedPublicKey as XOnlyPublicKey};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::blockdata::transaction::Sequence;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn random_keypair(
        rng: &mut impl Rng,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> (Keypair, XOnlyPublicKey) {
        let mut bytes = [0u8; 32];
        loop {
            rng.fill(&mut bytes);
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                let kp = Keypair::from_secret_key(secp, &sk);
                let (pk, _) = kp.x_only_public_key();
                return (kp, pk);
            }
        }
    }

    #[test]
    fn test_build_disprove_tx() {
        let kickoff_txid = Txid::all_zeros();
        let tx = build_disprove_tx(kickoff_txid);

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output.vout, 0);
        assert!(tx.input[0].witness.is_empty());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::ZERO);
        assert!(tx.output[0].script_pubkey.is_op_return());
    }

    #[test]
    fn test_witness_disprove_tx() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let (_, operator_pk) = random_keypair(&mut rng, &secp);

        let secret = [0xab; 20];
        let secret_hash = hash160::Hash::hash(&secret).to_byte_array();
        let timeout = Sequence::from_height(10);

        let spend_info = scripts::connector_spend_info(
            &secp, operator_pk, secret_hash, timeout,
        ).unwrap();

        let kickoff_txid = Txid::all_zeros();
        let mut tx = build_disprove_tx(kickoff_txid);
        witness_disprove_tx(&mut tx, secret, secret_hash, &spend_info).unwrap();

        // Witness: preimage + script + control block
        assert_eq!(tx.input[0].witness.len(), 3);
        assert_eq!(tx.input[0].witness[0], secret);

        use crate::network::BITCOIN_NETWORK;
        let connector_prevout = TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        };
        BITCOIN_NETWORK
            .verify_input(&tx, 0, &[connector_prevout])
            .unwrap();
    }

    #[test]
    fn test_disprove_wrong_preimage_rejected() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let (_, operator_pk) = random_keypair(&mut rng, &secp);

        let secret = [0xab; 20];
        let secret_hash = hash160::Hash::hash(&secret).to_byte_array();
        let timeout = Sequence::from_height(10);

        let spend_info = scripts::connector_spend_info(
            &secp, operator_pk, secret_hash, timeout,
        ).unwrap();

        let kickoff_txid = Txid::all_zeros();
        let mut tx = build_disprove_tx(kickoff_txid);

        // Use wrong preimage
        let wrong_secret = [0xcc; 20];
        witness_disprove_tx(&mut tx, wrong_secret, secret_hash, &spend_info).unwrap();

        use crate::network::BITCOIN_NETWORK;
        let connector_prevout = TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        };
        assert!(
            BITCOIN_NETWORK.verify_input(&tx, 0, &[connector_prevout]).is_err(),
            "wrong hash preimage should be rejected"
        );
    }
}
