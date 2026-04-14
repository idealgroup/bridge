use std::sync::Arc;

use bitcoin::transaction::Transaction;
use bitcoin::secp256k1::{All, Secp256k1};
use crate::BridgeError;

pub struct BitcoinNetwork {
    node: Arc<crate::regtest::RegtestNode>,
}

impl BitcoinNetwork {
    /// Start a fresh isolated regtest node (mines 101 blocks for coinbase maturity).
    /// Each call creates a new bitcoind process — use for tests that need isolation.
    pub fn new_regtest() -> Result<Self, BridgeError> {
        let node = crate::regtest::RegtestNode::start()?;
        node.mine_blocks(101)?;
        Ok(Self {
            node: Arc::new(node),
        })
    }

    /// Fund a P2TR address with a real funded UTXO.
    pub fn fund_p2tr(
        &self,
        secp: &Secp256k1<All>,
        pubkey: bitcoin::key::UntweakedPublicKey,
        amount: bitcoin::Amount,
    ) -> Result<bitcoin::OutPoint, BridgeError> {
        let addr = bitcoin::Address::p2tr(secp, pubkey, None, bitcoin::Network::Regtest);
        self.node.fund_address(&addr, amount)
    }

    /// Mine n blocks.
    pub fn mine_blocks(&self, n: u64) -> Result<(), BridgeError> {
        self.node.mine_blocks(n)
    }

    /// Broadcast a transaction without mining.
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<bitcoin::Txid, BridgeError> {
        self.node.send_transaction(tx)
    }

    /// Fetch a transaction by txid.
    pub fn get_raw_transaction(&self, txid: &bitcoin::Txid) -> Result<Transaction, BridgeError> {
        use bitcoincore_rpc::RpcApi;
        self.node
            .client
            .get_raw_transaction(txid, None)
            .map_err(|e| BridgeError::Regtest(format!("get_raw_transaction: {e}")))
    }

    /// Get a block at the given height.
    pub fn get_block_at_height(&self, height: u64) -> Result<bitcoin::Block, BridgeError> {
        use bitcoincore_rpc::RpcApi;
        let hash = self
            .node
            .client
            .get_block_hash(height)
            .map_err(|e| BridgeError::Regtest(format!("get_block_hash: {e}")))?;
        self.node
            .client
            .get_block(&hash)
            .map_err(|e| BridgeError::Regtest(format!("get_block: {e}")))
    }

    /// Get the current chain tip height.
    pub fn get_chain_tip(&self) -> Result<u64, BridgeError> {
        use bitcoincore_rpc::RpcApi;
        self.node
            .client
            .get_block_count()
            .map_err(|e| BridgeError::Regtest(format!("get_block_count: {e}")))
    }

    /// Fetch all blocks from `from_height` through the current tip (inclusive).
    pub fn poll_new_blocks(&self, from_height: u64) -> Result<Vec<bitcoin::Block>, BridgeError> {
        let tip = self.get_chain_tip()?;
        let mut blocks = Vec::new();
        for h in from_height..=tip {
            blocks.push(self.get_block_at_height(h)?);
        }
        Ok(blocks)
    }
}
