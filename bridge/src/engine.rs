use crate::BridgeError;

pub type Proof = [u8; 256];
pub type DisproveSecret = [u8; 20];

pub trait BitVMEngine {
    fn verify_proof(&self, proof: &Proof) -> Result<bool, BridgeError>;
    fn extract_disprove_secret(
        &self,
        proof: &Proof,
        lamport_pk: &lamport::PublicKey,
    ) -> Result<Option<DisproveSecret>, BridgeError>;
}

/// Mock engine: proof is valid iff proof[0] == 0x00.
/// For invalid proofs, the disprove secret is proof[0..20].
pub struct MockEngine;

impl BitVMEngine for MockEngine {
    fn verify_proof(&self, proof: &Proof) -> Result<bool, BridgeError> {
        Ok(proof[0] == 0x00)
    }

    fn extract_disprove_secret(
        &self,
        proof: &Proof,
        _lamport_pk: &lamport::PublicKey,
    ) -> Result<Option<DisproveSecret>, BridgeError> {
        if proof[0] == 0x00 {
            Ok(None)
        } else {
            let mut secret = [0u8; 20];
            secret.copy_from_slice(&proof[0..20]);
            Ok(Some(secret))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk() -> Box<lamport::PublicKey> {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(1);
        let sk = lamport::SecretKey::random(&mut rng);
        sk.public_key()
    }

    #[test]
    fn test_mock_valid_proof() {
        let engine = MockEngine;
        let mut proof = [0u8; 256];
        proof[0] = 0x00;
        assert!(engine.verify_proof(&proof).unwrap());
        let pk = dummy_pk();
        assert!(engine.extract_disprove_secret(&proof, &pk).unwrap().is_none());
    }

    #[test]
    fn test_mock_invalid_proof() {
        let engine = MockEngine;
        let mut proof = [0u8; 256];
        proof[0] = 0xFF;
        assert!(!engine.verify_proof(&proof).unwrap());
        let pk = dummy_pk();
        let secret = engine.extract_disprove_secret(&proof, &pk).unwrap();
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().len(), 20);
    }
}
