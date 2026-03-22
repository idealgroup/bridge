use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use rand::rngs::StdRng;
use rand::SeedableRng;

pub fn test_rng() -> StdRng {
    StdRng::seed_from_u64(42)
}

pub fn test_rng_seeded(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

pub fn dummy_outpoint() -> OutPoint {
    OutPoint::new(Txid::all_zeros(), 0)
}
