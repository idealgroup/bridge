use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::network::EthereumWallet;

use super::MintingContract;

/// Pre-funded anvil account #0 (default mnemonic).
const ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub struct AnvilNode {
    pub url: String,
    process: Mutex<Option<Child>>,
    pub wallet: EthereumWallet,
}

impl AnvilNode {
    /// Spawn a fresh anvil subprocess on a free port and wait until it is
    /// serving JSON-RPC requests.
    pub async fn start() -> Self {
        // Ensure the Solidity artifacts exist.
        Self::build_contract_artifacts();

        let port = free_port();
        let child = Command::new("anvil")
            .arg("--port")
            .arg(port.to_string())
            .arg("--host")
            .arg("127.0.0.1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn anvil");

        let url = format!("http://127.0.0.1:{port}");

        let signer: PrivateKeySigner = ANVIL_PRIVATE_KEY.parse().unwrap();
        let wallet = EthereumWallet::from(signer.clone());

        // Poll until ready.
        let start = Instant::now();
        let timeout = Duration::from_secs(15);
        loop {
            if start.elapsed() > timeout {
                panic!("anvil did not become ready within 15s");
            }
            let provider = ProviderBuilder::new()
                .wallet(wallet.clone())
                .connect_http(url.parse().unwrap());
            if provider.get_chain_id().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Self {
            url,
            process: Mutex::new(Some(child)),
            wallet,
        }
    }

    /// Build the Solidity artifacts via `forge build` in the `ethereum/` directory.
    /// Called once at anvil start so we don't need to maintain a separate build step.
    pub fn build_contract_artifacts() {
        let project_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| std::path::PathBuf::from(d).parent().unwrap().to_path_buf())
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let ethereum_dir = project_root.join("ethereum");

        let status = Command::new("forge")
            .arg("build")
            .current_dir(&ethereum_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .expect("failed to run forge build");
        assert!(status.success(), "forge build failed");
    }

    /// Construct an HTTP provider backed by the default anvil account.
    pub fn provider(&self) -> impl Provider + Clone + WalletProvider {
        ProviderBuilder::new()
            .wallet(self.wallet.clone())
            .connect_http(self.url.parse().unwrap())
    }

    /// Deploy a fresh `MintingContract` with the given committee keys, deposit size, and mint delay.
    /// `mint_delay` is in seconds (the contract uses `block.timestamp`).
    pub async fn deploy_minting_contract(
        &self,
        committee_internal_pk: B256,
        deposit_tweaked_pk: B256,
        deposit_size: u64,
        mint_delay: u64,
    ) -> Address {
        let provider = self.provider();
        let instance = MintingContract::deploy(&provider, committee_internal_pk, deposit_tweaked_pk, deposit_size, mint_delay)
            .await
            .expect("deploy failed");
        *instance.address()
    }

    /// Advance the anvil chain's `block.timestamp` by `seconds` and mine a block.
    /// Used to simulate the mint delay (the contract checks `block.timestamp`).
    pub async fn increase_time(&self, seconds: u64) {
        let provider = self.provider();
        // `evm_increaseTime` returns the new offset as a string; accept anything.
        let _: serde_json::Value = provider
            .client()
            .request("evm_increaseTime", (seconds,))
            .await
            .expect("evm_increaseTime failed");

        // anvil's `evm_mine` returns the string "0x0" which doesn't parse as B256.
        let _: serde_json::Value = provider
            .client()
            .request("evm_mine", ())
            .await
            .expect("evm_mine failed");
    }

}

impl Drop for AnvilNode {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.process.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind for free port");
    listener.local_addr().unwrap().port()
}
