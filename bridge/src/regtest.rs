use std::net::TcpListener;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::consensus::encode;
use bitcoin::{Address, Amount, OutPoint, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::BridgeError;

pub struct RegtestNode {
    pub client: Client,
    process: std::sync::Mutex<Option<Child>>,
    // Held for Drop — TempDir removes on drop
    #[allow(dead_code)]
    datadir: Option<tempfile::TempDir>,
}

impl RegtestNode {
    /// Spawn a fresh bitcoind regtest node with a temporary datadir.
    pub fn start() -> Result<Self, BridgeError> {
        let bitcoind = which_bitcoind()?;
        let datadir = tempfile::TempDir::new()
            .map_err(|e| BridgeError::Regtest(format!("tempdir: {e}")))?;

        let port = free_port()?;
        let rpc_user = "idealtest";
        let rpc_pass = "idealtest";

        // Write bitcoin.conf.
        //
        // `minrelaytxfee=0` + `blockmintxfee=0` are load-bearing: the
        // depositor's `requestTx` has zero fee (see
        // `depositor::request::build_request_tx` and
        // `bridge::params::Params::request_input_value`). Default bitcoind
        // relay policy would reject it.
        let conf_path = datadir.path().join("bitcoin.conf");
        std::fs::write(
            &conf_path,
            format!(
                "regtest=1\n\
                 server=1\n\
                 rpcuser={rpc_user}\n\
                 rpcpassword={rpc_pass}\n\
                 txindex=1\n\
                 fallbackfee=0.00001\n\
                 minrelaytxfee=0\n\
                 blockmintxfee=0\n\
                 listen=0\n"
            ),
        )
        .map_err(|e| BridgeError::Regtest(format!("write bitcoin.conf: {e}")))?;

        let mut cmd = Command::new(&bitcoind);
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", datadir.path().display()))
            .arg(format!("-rpcport={port}"))
            .arg("-daemon=0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        // macOS can report a huge RLIMIT_NOFILE soft limit that bitcoind's
        // setrlimit cannot raise to, leaving it with -1 available FDs.
        // Set a sane limit before exec so bitcoind starts correctly.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    let limit = libc::rlimit { rlim_cur: 4096, rlim_max: 4096 };
                    libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
                    Ok(())
                });
            }
        }

        let child = cmd
            .spawn()
            .map_err(|e| BridgeError::Regtest(format!("spawn bitcoind: {e}")))?;

        let url = format!("http://127.0.0.1:{port}");
        let client = Client::new(
            &url,
            Auth::UserPass(rpc_user.into(), rpc_pass.into()),
        )
        .map_err(|e| BridgeError::Regtest(format!("rpc client: {e}")))?;

        // Poll until ready
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        loop {
            if start.elapsed() > timeout {
                return Err(BridgeError::Regtest(
                    "bitcoind did not become ready within 10s".into(),
                ));
            }
            if client.get_blockchain_info().is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        // Create a fresh default wallet. The tempdir is new so the wallet cannot
        // already exist — any failure here is a real problem and should surface.
        client
            .create_wallet("default", None, None, None, None)
            .map_err(|e| BridgeError::Regtest(format!("create_wallet: {e}")))?;

        Ok(Self {
            client,
            process: std::sync::Mutex::new(Some(child)),
            datadir: Some(datadir),
        })
    }

    /// Broadcast a fully-signed transaction.
    pub fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BridgeError> {
        let hex = encode::serialize_hex(tx);
        self.client
            .send_raw_transaction(hex)
            .map_err(|e| BridgeError::Regtest(format!("send_raw_transaction: {e}")))
    }

    /// Mine `n` blocks to an internal wallet address.
    pub fn mine_blocks(&self, n: u64) -> Result<(), BridgeError> {
        let addr = self
            .client
            .get_new_address(None, None)
            .map_err(|e| BridgeError::Regtest(format!("get_new_address: {e}")))?
            .assume_checked();
        self.client
            .generate_to_address(n, &addr)
            .map_err(|e| BridgeError::Regtest(format!("generate_to_address: {e}")))?;
        Ok(())
    }

    /// Check whether a transaction would be accepted to the mempool.
    /// Returns (allowed, reject_reason).
    pub fn test_mempool_accept(&self, tx: &Transaction) -> Result<(bool, Option<String>), BridgeError> {
        let hex = encode::serialize_hex(tx);
        let results = self
            .client
            .test_mempool_accept(&[hex])
            .map_err(|e| BridgeError::Regtest(format!("test_mempool_accept: {e}")))?;
        let result = results.first();
        let allowed = result.is_some_and(|r| r.allowed);
        let reason = result.and_then(|r| r.reject_reason.clone());
        Ok((allowed, reason))
    }

    /// Send coins to an address and mine one block to confirm.
    /// Returns the outpoint of the funded output.
    pub fn fund_address(
        &self,
        addr: &Address,
        amount: Amount,
    ) -> Result<OutPoint, BridgeError> {
        let txid = self
            .client
            .send_to_address(addr, amount, None, None, None, None, None, None)
            .map_err(|e| BridgeError::Regtest(format!("send_to_address: {e}")))?;
        self.mine_blocks(1)?;

        // Find the vout that pays to our address.
        // Use get_raw_transaction (not _info) to avoid JSON parsing issues
        // with output types that bitcoincore-rpc 0.19 doesn't understand.
        let funded_tx = self
            .client
            .get_raw_transaction(&txid, None)
            .map_err(|e| BridgeError::Regtest(format!("get_raw_transaction: {e}")))?;

        let target_spk = addr.script_pubkey();
        let vout = funded_tx
            .output
            .iter()
            .position(|o| o.script_pubkey == target_spk)
            .ok_or_else(|| BridgeError::Regtest("funded output not found".into()))?;

        Ok(OutPoint::new(txid, vout as u32))
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.process.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        // TempDir auto-cleans on drop
    }
}

fn which_bitcoind() -> Result<String, BridgeError> {
    let output = Command::new("which")
        .arg("bitcoind")
        .output()
        .map_err(|e| BridgeError::Regtest(format!("which bitcoind: {e}")))?;
    if !output.status.success() {
        return Err(BridgeError::Regtest(
            "bitcoind not found in PATH".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn free_port() -> Result<u16, BridgeError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| BridgeError::Regtest(format!("bind for free port: {e}")))?;
    Ok(listener.local_addr().unwrap().port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_and_mine() {
        let node = RegtestNode::start().expect("failed to start regtest node");
        node.mine_blocks(101).expect("failed to mine blocks");
        let info = node.client.get_blockchain_info().unwrap();
        assert_eq!(info.blocks, 101);
    }

    #[test]
    fn test_fund_and_spend() {
        use bitcoin::key::{TapTweak, UntweakedKeypair};
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Network, TxIn, TxOut, Witness};

        let secp = Secp256k1::new();
        let node = RegtestNode::start().expect("failed to start regtest node");
        node.mine_blocks(101).expect("mine for maturity");

        // Generate a keypair and P2TR address
        let sk = bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng());
        let kp = UntweakedKeypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = kp.x_only_public_key();
        let addr = Address::p2tr(&secp, xonly, None, Network::Regtest);

        // Fund the address
        let outpoint = node
            .fund_address(&addr, Amount::from_sat(100_000))
            .expect("fund_address");

        // Build a spend tx
        let spend_addr = node
            .client
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();

        let prevout_value = Amount::from_sat(100_000);
        let fee = Amount::from_sat(1_000);

        let mut spend_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: prevout_value - fee,
                script_pubkey: spend_addr.script_pubkey(),
            }],
        };

        // Sign (key-spend, no merkle root)
        let prevouts = vec![TxOut {
            value: prevout_value,
            script_pubkey: addr.script_pubkey(),
        }];

        let merkle_root = None;
        let tweaked = kp.tap_tweak(&secp, merkle_root);
        let signing_kp = tweaked.to_keypair();

        let mut cache = SighashCache::new(&spend_tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .expect("sighash");

        use bitcoin::hashes::Hash;
        let msg =
            bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &signing_kp);

        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        spend_tx.input[0].witness = witness;

        // Send and confirm
        let txid = node.send_transaction(&spend_tx).expect("send_transaction");
        node.mine_blocks(1).expect("mine confirmation");

        // Tx should be confirmed (findable) and not in mempool
        assert!(node.client.get_raw_transaction(&txid, None).is_ok());
        assert!(node.client.get_mempool_entry(&txid).is_err());
    }

    #[test]
    fn test_mempool_accept_rejects_invalid() {
        let node = RegtestNode::start().expect("failed to start regtest node");
        node.mine_blocks(1).expect("mine genesis");

        // Build a tx spending a nonexistent UTXO
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::new(
                    "0000000000000000000000000000000000000000000000000000000000000001"
                        .parse()
                        .unwrap(),
                    0,
                ),
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let (accepted, _reason) = node.test_mempool_accept(&tx).expect("test_mempool_accept");
        assert!(!accepted);
    }
}
