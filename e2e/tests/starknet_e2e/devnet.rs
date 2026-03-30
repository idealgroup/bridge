use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use starknet::accounts::{ExecutionEncoding, SingleOwnerAccount};
use starknet::contract::{ContractFactory, UdcSelector};
use starknet::core::types::{BlockId, BlockTag, Felt};
use starknet::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet::providers::{Provider, Url};
use starknet::signers::{LocalWallet, SigningKey};

pub type StarknetAccount = SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>;

pub struct DevnetNode {
    pub url: String,
    pub provider: Arc<JsonRpcClient<HttpTransport>>,
    process: Mutex<Option<Child>>,
}

impl DevnetNode {
    /// Spawn a fresh starknet-devnet node on a free port with deterministic seed.
    pub async fn start() -> Self {
        let port = free_port();
        let devnet_bin = which_starknet_devnet();

        let child = Command::new(&devnet_bin)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--seed")
            .arg("0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn starknet-devnet");

        let url = format!("http://127.0.0.1:{port}");
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            Url::parse(&url).unwrap(),
        )));

        // Poll until ready
        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        loop {
            if start.elapsed() > timeout {
                panic!("starknet-devnet did not become ready within 30s");
            }
            match provider.chain_id().await {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }

        Self {
            url,
            provider,
            process: Mutex::new(Some(child)),
        }
    }

    /// Get a SingleOwnerAccount for the first predeployed account (seed=0).
    pub async fn predeployed_account(&self) -> StarknetAccount {
        let (address, private_key) = self.fetch_predeployed_credentials().await;
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
        let chain_id = self.provider.chain_id().await.unwrap();

        let mut account = SingleOwnerAccount::new(
            self.provider.clone(),
            signer,
            address,
            chain_id,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
        account
    }

    /// Fetch the first predeployed account credentials from devnet JSON-RPC.
    async fn fetch_predeployed_credentials(&self) -> (Felt, Felt) {
        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .post(&self.url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "method": "devnet_getPredeployedAccounts",
                "params": {}
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let accounts = resp["result"].as_array().expect("expected accounts array");
        let first = &accounts[0];
        let address = Felt::from_hex(first["address"].as_str().unwrap()).unwrap();
        let private_key = Felt::from_hex(first["private_key"].as_str().unwrap()).unwrap();
        (address, private_key)
    }

    /// Advance block time by `seconds` and generate a new block.
    pub async fn increase_time(&self, seconds: u64) {
        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .post(&self.url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "1",
                "method": "devnet_increaseTime",
                "params": {
                    "time": seconds
                }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert!(
            resp.get("error").is_none(),
            "devnet_increaseTime failed: {resp}"
        );
    }

    /// Run `scarb build` in the starknet/ directory to produce Sierra + CASM artifacts.
    pub fn build_contract_artifacts() {
        let project_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| std::path::PathBuf::from(d).parent().unwrap().to_path_buf())
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let starknet_dir = project_root.join("starknet");

        let status = Command::new("scarb")
            .arg("build")
            .current_dir(&starknet_dir)
            .status()
            .expect("failed to run scarb build");
        assert!(status.success(), "scarb build failed");
    }

    /// Declare and deploy the MintingContract.
    ///
    /// Uses `sncast declare` for the declare step (handles CASM class hash computation
    /// correctly for Cairo 2.16.1 artifacts, unlike starknet-core 0.16.0).
    ///
    /// Constructor args: `(committee_pubkey: u256, mint_delay: u64)`
    /// Returns the deployed contract address.
    pub async fn declare_and_deploy(
        &self,
        committee_pubkey_low: Felt,
        committee_pubkey_high: Felt,
        mint_delay: u64,
    ) -> Felt {
        let project_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| std::path::PathBuf::from(d).parent().unwrap().to_path_buf())
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let starknet_dir = project_root.join("starknet");

        // Set up a temporary sncast accounts file with the devnet predeployed account
        let (address, private_key) = self.fetch_predeployed_credentials().await;
        let port: u16 = self.url.rsplit(':').next().unwrap().parse().unwrap();
        let tmp_dir = std::env::temp_dir().join(format!("ideal-e2e-{port}"));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let accounts_file = tmp_dir.join("accounts.json");
        std::fs::write(&accounts_file, "{}").unwrap();

        let import_output = Command::new("sncast")
            .arg("--accounts-file").arg(&accounts_file)
            .arg("account")
            .arg("import")
            .arg("--name").arg("devnet")
            .arg("--address").arg(format!("{address:#x}"))
            .arg("--type").arg("oz")
            .arg("--private-key").arg(format!("{private_key:#x}"))
            .arg("--url").arg(&self.url)
            .arg("--silent")
            .output()
            .expect("sncast account import failed to run");
        assert!(
            import_output.status.success(),
            "sncast account import failed: {}",
            String::from_utf8_lossy(&import_output.stderr)
        );

        // Declare via sncast (correctly computes CASM class hash)
        let declare_output = Command::new("sncast")
            .arg("--json")
            .arg("--account").arg("devnet")
            .arg("--accounts-file").arg(&accounts_file)
            .arg("--wait")
            .arg("--wait-timeout").arg("30")
            .arg("declare")
            .arg("--contract-name").arg("MintingContract")
            .arg("--url").arg(&self.url)
            .current_dir(&starknet_dir)
            .output()
            .expect("sncast declare failed to run");
        assert!(
            declare_output.status.success(),
            "sncast declare failed: {}{}",
            String::from_utf8_lossy(&declare_output.stdout),
            String::from_utf8_lossy(&declare_output.stderr)
        );

        // sncast --json --wait outputs multiple JSON lines (NDJSON); parse the one with class_hash
        let stdout = String::from_utf8_lossy(&declare_output.stdout);
        let class_hash = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find_map(|v| v["class_hash"].as_str().map(String::from))
            .expect("class_hash not found in sncast declare output");
        let class_hash = Felt::from_hex(&class_hash).expect("parse class_hash");

        // Deploy via ContractFactory (UDC)
        // Constructor: (committee_pubkey: u256, mint_delay: u64)
        // u256 serialized as (low, high) in calldata
        let constructor_calldata = vec![
            committee_pubkey_low,
            committee_pubkey_high,
            Felt::from(mint_delay),
        ];

        let deploy_account = self.predeployed_account().await;
        let factory = ContractFactory::new_with_udc(class_hash, deploy_account, UdcSelector::New);
        let deployment = factory.deploy_v3(constructor_calldata, Felt::ZERO, false);
        let contract_address = deployment.deployed_address();
        let deploy_result = deployment.send().await.expect("deploy failed");
        wait_for_tx(&self.provider, deploy_result.transaction_hash).await;

        // Clean up temp files
        let _ = std::fs::remove_dir_all(&tmp_dir);

        contract_address
    }
}

impl Drop for DevnetNode {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.process.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Wait for a transaction to be accepted (any status).
pub async fn wait_for_tx(provider: &JsonRpcClient<HttpTransport>, tx_hash: Felt) {
    let start = Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        if start.elapsed() > timeout {
            panic!("transaction {tx_hash:#x} not confirmed within 30s");
        }
        if provider.get_transaction_receipt(tx_hash).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn which_starknet_devnet() -> String {
    let output = Command::new("which")
        .arg("starknet-devnet")
        .output()
        .expect("which starknet-devnet failed");
    assert!(
        output.status.success(),
        "starknet-devnet not found in PATH"
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind for free port");
    listener.local_addr().unwrap().port()
}
