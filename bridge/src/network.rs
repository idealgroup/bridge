#[cfg(test)]
use bitcoin::transaction::Transaction;
#[cfg(test)]
use bitcoin::secp256k1::{All, Secp256k1};
#[cfg(test)]
use crate::BridgeError;

pub enum BitcoinNetworkMode {
    Regtest,
}

pub struct BitcoinNetwork {
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub(crate) fn poll_new_blocks(&self, from_height: u64) -> Result<Vec<bitcoin::Block>, BridgeError> {
        let tip = self.get_chain_tip()?;
        let mut blocks = Vec::new();
        for h in from_height..=tip {
            blocks.push(self.get_block_at_height(h)?);
        }
        Ok(blocks)
    }
}

#[cfg(test)]
pub(crate) static BITCOIN_NETWORK: std::sync::LazyLock<BitcoinNetwork> =
    std::sync::LazyLock::new(|| BitcoinNetwork::new(BitcoinNetworkMode::Regtest));
