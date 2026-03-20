use bitcoin::transaction::{Transaction, TxOut};
#[cfg(test)]
use bitcoin::secp256k1::{All, Secp256k1};

use crate::BridgeError;

pub enum BitcoinNetworkMode {
    Regtest,
}

pub struct BitcoinNetwork {
    mode: BitcoinNetworkMode,
}

#[cfg(test)]
pub(crate) static REGTEST_NODE: std::sync::LazyLock<crate::regtest::RegtestNode> =
    std::sync::LazyLock::new(|| {
        let node = crate::regtest::RegtestNode::start().expect("start regtest node");
        node.mine_blocks(101).expect("mine for coinbase maturity");
        node
    });

impl BitcoinNetwork {
    pub fn new(mode: BitcoinNetworkMode) -> Self {
        Self { mode }
    }

    /// Verify a single input's witness against its spending condition.
    pub fn verify_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevouts: &[TxOut],
    ) -> Result<(), BridgeError> {
        match &self.mode {
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

    /// Fund a P2TR address with a real funded UTXO.
    #[cfg(test)]
    pub(crate) fn fund_p2tr(
        &self,
        secp: &Secp256k1<All>,
        pubkey: bitcoin::key::UntweakedPublicKey,
        amount: bitcoin::Amount,
    ) -> bitcoin::OutPoint {
        match &self.mode {
            BitcoinNetworkMode::Regtest => {
                let addr = bitcoin::Address::p2tr(secp, pubkey, None, bitcoin::Network::Regtest);
                REGTEST_NODE.fund_address(&addr, amount).expect("fund_p2tr")
            }
        }
    }

    /// Broadcast tx and mine 1 block.
    #[cfg(test)]
    pub(crate) fn confirm_tx(&self, tx: &Transaction) {
        match &self.mode {
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

    /// Mine n blocks.
    #[cfg(test)]
    pub(crate) fn mine_blocks(&self, n: u64) {
        match &self.mode {
            BitcoinNetworkMode::Regtest => {
                REGTEST_NODE.mine_blocks(n).expect("mine_blocks");
            }
        }
    }

    /// Broadcast a transaction without mining.
    #[cfg(test)]
    pub(crate) fn broadcast_tx(&self, tx: &Transaction) -> Result<bitcoin::Txid, BridgeError> {
        match &self.mode {
            BitcoinNetworkMode::Regtest => REGTEST_NODE.send_transaction(tx),
        }
    }

    /// Fetch a transaction by txid.
    #[cfg(test)]
    pub(crate) fn get_raw_transaction(&self, txid: &bitcoin::Txid) -> Result<Transaction, BridgeError> {
        match &self.mode {
            BitcoinNetworkMode::Regtest => {
                use bitcoincore_rpc::RpcApi;
                REGTEST_NODE
                    .client
                    .get_raw_transaction(txid, None)
                    .map_err(|e| BridgeError::Regtest(format!("get_raw_transaction: {e}")))
            }
        }
    }

    /// Get a block at the given height.
    #[cfg(test)]
    pub(crate) fn get_block_at_height(&self, height: u64) -> Result<bitcoin::Block, BridgeError> {
        match &self.mode {
            BitcoinNetworkMode::Regtest => {
                use bitcoincore_rpc::RpcApi;
                let hash = REGTEST_NODE
                    .client
                    .get_block_hash(height)
                    .map_err(|e| BridgeError::Regtest(format!("get_block_hash: {e}")))?;
                REGTEST_NODE
                    .client
                    .get_block(&hash)
                    .map_err(|e| BridgeError::Regtest(format!("get_block: {e}")))
            }
        }
    }

    /// Get the current chain tip height.
    #[cfg(test)]
    pub(crate) fn get_chain_tip(&self) -> Result<u64, BridgeError> {
        match &self.mode {
            BitcoinNetworkMode::Regtest => {
                use bitcoincore_rpc::RpcApi;
                REGTEST_NODE
                    .client
                    .get_block_count()
                    .map_err(|e| BridgeError::Regtest(format!("get_block_count: {e}")))
            }
        }
    }

    /// Fetch all blocks from `from_height` through the current tip (inclusive).
    #[cfg(test)]
    pub(crate) fn poll_new_blocks(&self, from_height: u64) -> Result<Vec<bitcoin::Block>, BridgeError> {
        let tip = self.get_chain_tip()?;
        let mut blocks = Vec::new();
        for h in from_height..=tip {
            blocks.push(self.get_block_at_height(h)?);
        }
        Ok(blocks)
    }

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
}

#[cfg(test)]
pub(crate) static BITCOIN_NETWORK: std::sync::LazyLock<BitcoinNetwork> =
    std::sync::LazyLock::new(|| BitcoinNetwork::new(BitcoinNetworkMode::Regtest));
