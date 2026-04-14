use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::network::BitcoinNetwork;

pub fn test_rng() -> StdRng {
    StdRng::seed_from_u64(42)
}

pub fn test_rng_seeded(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

pub fn dummy_outpoint() -> OutPoint {
    OutPoint::new(Txid::all_zeros(), 0)
}

/// Shared regtest network for tests that don't need isolation. Spins up a single
/// bitcoind process on first access and reuses it across the test binary.
///
/// Tests that need an isolated chain (e.g. to avoid CSV/CLTV timing coupling)
/// should use [`BitcoinNetwork::new_regtest`] directly instead.
pub static BITCOIN_NETWORK: std::sync::LazyLock<BitcoinNetwork> =
    std::sync::LazyLock::new(|| BitcoinNetwork::new_regtest().expect("start shared regtest node"));
