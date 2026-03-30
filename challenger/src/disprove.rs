use bitcoin::absolute::LockTime;
use bitcoin::taproot::{LeafVersion, TaprootSpendInfo};
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, ScriptBuf, Txid, Witness};

use bridge::scripts;
use bridge::BridgeError;

/// Builds an unsigned disprove transaction.
///
/// - Input: kickoffTx.out[0] (connector), script-path with hash preimage (no sig)
/// - Output: OP_RETURN (burns the connector)
pub fn build_disprove_tx(kickoff_txid: Txid) -> Transaction {
    // Pad OP_RETURN to meet MIN_STANDARD_TX_NONWITNESS_SIZE (65 bytes).
    let op_return = ScriptBuf::new_op_return([0u8; 4]);

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
    disprove_secret_hash: [u8; 32],
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
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

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
}
