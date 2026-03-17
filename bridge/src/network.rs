use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::{Transaction, TxOut};
use bitcoin::ScriptBuf;

use crate::BridgeError;

pub enum BitcoinNetworkMode {
    ScriptExec,
    #[cfg(feature = "regtest")]
    Regtest,
}

pub struct BitcoinNetwork {
    mode: BitcoinNetworkMode,
    secp: Secp256k1<All>,
}

#[cfg(all(test, feature = "regtest"))]
pub(crate) static REGTEST_NODE: std::sync::LazyLock<crate::regtest::RegtestNode> =
    std::sync::LazyLock::new(|| {
        let node = crate::regtest::RegtestNode::start().expect("start regtest node");
        node.mine_blocks(101).expect("mine for coinbase maturity");
        node
    });

impl BitcoinNetwork {
    pub fn new(mode: BitcoinNetworkMode) -> Self {
        Self {
            mode,
            secp: Secp256k1::new(),
        }
    }

    /// Verify a single input's witness against its spending condition.
    pub fn verify_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
    ) -> Result<(), BridgeError> {
        match &self.mode {
            BitcoinNetworkMode::ScriptExec => {
                self.verify_input_scriptexec(tx, input_index, prevouts)
            }
            #[cfg(feature = "regtest")]
            BitcoinNetworkMode::Regtest => {
                self.verify_input_regtest(tx, input_index, prevouts)
            }
        }
    }

    /// Verify all inputs in a transaction.
    pub fn verify_tx(&self, tx: &Transaction, prevouts: &[TxOut]) -> Result<(), BridgeError> {
        for i in 0..tx.input.len() {
            self.verify_input(tx, i, prevouts)?;
        }
        Ok(())
    }

    /// Fund a P2TR address. ScriptExec: dummy outpoint. Regtest: real funded UTXO.
    #[cfg(test)]
    pub(crate) fn fund_p2tr(
        &self,
        secp: &Secp256k1<All>,
        pubkey: bitcoin::key::UntweakedPublicKey,
        amount: bitcoin::Amount,
    ) -> bitcoin::OutPoint {
        match &self.mode {
            BitcoinNetworkMode::ScriptExec => {
                let _ = (secp, pubkey, amount);
                bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0)
            }
            #[cfg(feature = "regtest")]
            BitcoinNetworkMode::Regtest => {
                let addr = bitcoin::Address::p2tr(secp, pubkey, None, bitcoin::Network::Regtest);
                REGTEST_NODE.fund_address(&addr, amount).expect("fund_p2tr")
            }
        }
    }

    /// Broadcast tx and mine 1 block. ScriptExec: no-op. Regtest: real broadcast.
    #[cfg(test)]
    pub(crate) fn confirm_tx(&self, tx: &Transaction) {
        match &self.mode {
            BitcoinNetworkMode::ScriptExec => { let _ = tx; }
            #[cfg(feature = "regtest")]
            BitcoinNetworkMode::Regtest => {
                use bitcoincore_rpc::RpcApi;
                let txid = tx.compute_txid();
                // Use get_raw_transaction (not _info) to avoid JSON parsing issues
                // with P2A outputs that bitcoincore-rpc 0.19 doesn't understand.
                match REGTEST_NODE.client.get_raw_transaction(&txid, None) {
                    Ok(_) => {
                        // Tx is known. If still in mempool, mine to confirm.
                        if REGTEST_NODE.client.get_mempool_entry(&txid).is_ok() {
                            REGTEST_NODE.mine_blocks(1).expect("confirm_tx: mine");
                        }
                    }
                    Err(_) => {
                        REGTEST_NODE.send_transaction(tx).unwrap_or_else(|e| panic!("confirm_tx: send {txid}: {e}"));
                        REGTEST_NODE.mine_blocks(1).expect("confirm_tx: mine");
                    }
                }
            }
        }
    }

    /// Mine n blocks. ScriptExec: no-op. Regtest: real mining.
    #[cfg(test)]
    pub(crate) fn mine_blocks(&self, n: u64) {
        match &self.mode {
            BitcoinNetworkMode::ScriptExec => { let _ = n; }
            #[cfg(feature = "regtest")]
            BitcoinNetworkMode::Regtest => {
                REGTEST_NODE.mine_blocks(n).expect("mine_blocks");
            }
        }
    }

    #[cfg(feature = "regtest")]
    fn verify_input_regtest(
        &self,
        tx: &Transaction,
        _input_index: usize,
        _prevouts: &[TxOut],
    ) -> Result<(), BridgeError> {
        #[cfg(test)]
        {
            use bitcoincore_rpc::RpcApi;
            // Already confirmed or in mempool? Skip.
            // Use get_raw_transaction (not _info) to avoid JSON parsing issues
            // with P2A outputs that bitcoincore-rpc 0.19 doesn't understand.
            let txid = tx.compute_txid();
            if REGTEST_NODE.client.get_raw_transaction(&txid, None).is_ok() {
                return Ok(());
            }
            // Validate via testmempoolaccept
            let (accepted, reason) = REGTEST_NODE.test_mempool_accept(tx)?;
            if !accepted {
                let reason = reason.unwrap_or_else(|| "unknown".into());
                return Err(BridgeError::Regtest(format!("testmempoolaccept rejected: {reason}")));
            }
            // Broadcast + mine
            REGTEST_NODE.send_transaction(tx)?;
            REGTEST_NODE.mine_blocks(1)?;
            Ok(())
        }
        #[cfg(not(test))]
        {
            let _ = tx;
            Err(BridgeError::Regtest("regtest verify only available in tests".into()))
        }
    }

    fn verify_input_scriptexec(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
    ) -> Result<(), BridgeError> {
        let witness = &tx.input[input_index].witness;
        if witness.is_empty() {
            return Err(BridgeError::ScriptExecution("empty witness".into()));
        }

        let last = witness.last().unwrap();
        let is_script_path = last.len() >= 33 && (last[0] == 0xc0 || last[0] == 0xc1);

        if is_script_path {
            self.verify_script_path(tx, input_index, prevouts)
        } else {
            self.verify_key_spend(tx, input_index, prevouts)
        }
    }

    fn verify_key_spend(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
    ) -> Result<(), BridgeError> {
        let witness = &tx.input[input_index].witness;
        let sig_bytes = &witness[0];

        let sighash_type = if sig_bytes.len() == 64 {
            TapSighashType::Default
        } else if sig_bytes.len() == 65 {
            match sig_bytes[64] {
                0x01 => TapSighashType::All,
                0x02 => TapSighashType::None,
                0x03 => TapSighashType::Single,
                0x81 => TapSighashType::AllPlusAnyoneCanPay,
                0x82 => TapSighashType::NonePlusAnyoneCanPay,
                0x83 => TapSighashType::SinglePlusAnyoneCanPay,
                b => {
                    return Err(BridgeError::ScriptExecution(format!(
                        "invalid sighash byte: 0x{b:02x}"
                    )))
                }
            }
        } else {
            return Err(BridgeError::ScriptExecution(format!(
                "invalid key-spend sig length: {}",
                sig_bytes.len()
            )));
        };

        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes[..64])
            .map_err(|e| BridgeError::ScriptExecution(format!("invalid schnorr sig: {e}")))?;

        // Extract output key from P2TR script_pubkey: OP_1 OP_PUSHBYTES_32 <32-byte-key>
        let spk = &prevouts[input_index].script_pubkey;
        let spk_bytes = spk.as_bytes();
        if spk_bytes.len() != 34 || spk_bytes[0] != 0x51 || spk_bytes[1] != 0x20 {
            return Err(BridgeError::ScriptExecution("prevout is not P2TR".into()));
        }
        let output_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&spk_bytes[2..34])
            .map_err(|e| BridgeError::ScriptExecution(format!("invalid output key: {e}")))?;

        let mut cache = SighashCache::new(tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(prevouts),
                sighash_type,
            )
            .map_err(BridgeError::Sighash)?;
        let msg = Message::from_digest(*sighash.as_byte_array());

        self.secp
            .verify_schnorr(&sig, &msg, &output_key)
            .map_err(|e| {
                BridgeError::ScriptExecution(format!("key-spend verification failed: {e}"))
            })
    }

    fn verify_script_path(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
    ) -> Result<(), BridgeError> {
        use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

        let witness = &tx.input[input_index].witness;
        let n = witness.len();
        if n < 3 {
            return Err(BridgeError::ScriptExecution(
                "script-path witness too short".into(),
            ));
        }

        // Last element: control block, second-to-last: script, rest: stack
        let script = ScriptBuf::from(witness[n - 2].to_vec());
        let stack: Vec<Vec<u8>> = (0..n - 2).map(|i| witness[i].to_vec()).collect();

        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx: tx.clone(),
                prevouts: prevouts.to_vec(),
                input_idx: input_index,
                taproot_annex_scriptleaf: Some((leaf_hash, None)),
            },
            script,
            stack,
        )
        .map_err(|e| BridgeError::ScriptExecution(format!("scriptexec init: {e:?}")))?;

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }

        let result = exec.result().unwrap();
        if result.success {
            Ok(())
        } else {
            Err(BridgeError::ScriptExecution(format!(
                "script failed: {:?} at {:?}",
                result.error, result.opcode,
            )))
        }
    }
}

#[cfg(test)]
pub(crate) static BITCOIN_NETWORK: std::sync::LazyLock<BitcoinNetwork> = std::sync::LazyLock::new(|| {
    #[cfg(feature = "regtest")]
    { BitcoinNetwork::new(BitcoinNetworkMode::Regtest) }
    #[cfg(not(feature = "regtest"))]
    { BitcoinNetwork::new(BitcoinNetworkMode::ScriptExec) }
});
