use bitcoin::key::{Keypair, UntweakedPublicKey as XOnlyPublicKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::OutPoint;
use bitcoin::hashes::{sha256, Hash};
use rand::{CryptoRng, Rng};

use crate::BridgeError;

pub struct Operator {
    pub keypair: Keypair,
    pub pubkey: XOnlyPublicKey,
    pub init_utxo: OutPoint,
    pub lamport_keys: Vec<Box<lamport::SecretKey>>,
}

pub struct Depositor {
    pub keypair: Keypair,
    pub pubkey: XOnlyPublicKey,
    pub index: usize,
    pub request_utxo: OutPoint,
    pub deposit_secret: [u8; 32],
    /// 20-byte Ethereum address where wBTC will be minted (embedded in requestTx OP_RETURN).
    pub eth_address: [u8; 20],
}

pub struct Committee {
    pub keypair: Keypair,
    pub pubkey: XOnlyPublicKey,
}

fn random_keypair(
    rng: &mut (impl CryptoRng + Rng),
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Keypair {
    let mut secret_bytes = [0u8; 32];
    loop {
        rng.fill(&mut secret_bytes);
        if let Ok(sk) = SecretKey::from_slice(&secret_bytes) {
            return Keypair::from_secret_key(secp, &sk);
        }
    }
}

impl Operator {
    pub fn new(
        rng: &mut (impl CryptoRng + Rng),
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        init_utxo: OutPoint,
        deposit_count: usize,
    ) -> Self {
        let keypair = random_keypair(rng, secp);
        let (pubkey, _) = keypair.x_only_public_key();
        let lamport_keys = (0..deposit_count)
            .map(|_| lamport::SecretKey::random(rng))
            .collect();
        Self {
            keypair,
            pubkey,
            init_utxo,
            lamport_keys,
        }
    }

    pub fn lamport_pubkey(&self, slot: usize) -> Result<Box<lamport::PublicKey>, BridgeError> {
        self.lamport_keys
            .get(slot)
            .map(|sk| sk.public_key())
            .ok_or(BridgeError::IndexOutOfRange {
                name: "lamport slot",
                index: slot,
                max: self.lamport_keys.len(),
            })
    }
}

impl Depositor {
    pub fn new(
        rng: &mut (impl CryptoRng + Rng),
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        index: usize,
        request_utxo: OutPoint,
    ) -> Self {
        let keypair = random_keypair(rng, secp);
        let (pubkey, _) = keypair.x_only_public_key();
        let mut deposit_secret = [0u8; 32];
        rng.fill(&mut deposit_secret);
        let mut eth_address = [0u8; 20];
        rng.fill(&mut eth_address);
        Self {
            keypair,
            pubkey,
            index,
            request_utxo,
            deposit_secret,
            eth_address,
        }
    }

    pub fn deposit_secret_hash(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.deposit_secret).to_byte_array()
    }
}

impl Committee {
    pub fn new(
        rng: &mut (impl CryptoRng + Rng),
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> Self {
        let keypair = random_keypair(rng, secp);
        let (pubkey, _) = keypair.x_only_public_key();
        Self { keypair, pubkey }
    }
}

#[derive(Default)]
pub struct Challenger;

impl Challenger {
    pub fn new() -> Self {
        Challenger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{test_rng, dummy_outpoint};

    #[test]
    fn test_operator_creation() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let op = Operator::new(&mut rng, &secp, dummy_outpoint(), 4);
        assert_eq!(op.lamport_keys.len(), 4);
    }

    #[test]
    fn test_depositor_secret_hash() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let dep = Depositor::new(&mut rng, &secp, 0, dummy_outpoint());
        let hash = dep.deposit_secret_hash();
        assert_eq!(hash.len(), 32);
        // Deterministic
        let mut rng2 = test_rng();
        let dep2 = Depositor::new(&mut rng2, &secp, 0, dummy_outpoint());
        assert_eq!(dep.deposit_secret_hash(), dep2.deposit_secret_hash());
    }

    #[test]
    fn test_committee_creation() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let c = Committee::new(&mut rng, &secp);
        assert_ne!(c.pubkey.serialize(), [0u8; 32]);
    }
}
