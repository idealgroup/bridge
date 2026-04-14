use std::fmt;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::opcodes::all::*;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::{Builder, ScriptBuf};
use rand::{CryptoRng, Rng};

pub const MSG_LEN: usize = 256;
pub const NUM_BITS: usize = MSG_LEN * 8;
pub const PREIMAGE_LEN: usize = 20;
pub const HASH_LEN: usize = 32;

/// Maximum bits per chunk to stay within the tapscript 1000 stack item limit.
/// Each bit starts with one preimage on the stack, but verification temporarily
/// pushes 2 extra items (OP_DUP + pubkey hash), so peak usage is N + 2.
/// To keep peak ≤ 1000: N ≤ 998.
pub const MAX_BITS_PER_CHUNK: usize = 998;

/// Serialized size (in bytes) of the per-bit verification block produced by
/// [`PublicKey::verification_script_for_range`]. Layout per bit:
///
/// ```text
/// offset  bytes  opcode/data
/// 0       1      OP_SHA256
/// 1       1      OP_DUP
/// 2       1      OP_PUSHBYTES_32
/// 3..35   32     pk[i][0]            (hash for bit = 0)
/// 35      1      OP_EQUAL
/// 36      1      OP_IF
/// 37      1      OP_DROP
/// 38      1      OP_ELSE
/// 39      1      OP_PUSHBYTES_32
/// 40..72  32     pk[i][1]            (hash for bit = 1)
/// 72      1      OP_EQUALVERIFY
/// 73      1      OP_ENDIF
/// ```
pub const SCRIPT_BYTES_PER_BIT: usize = 74;
/// Byte offset of `pk[i][0]` (bit = 0 hash) within a bit's script block.
pub const SCRIPT_HASH0_OFFSET: usize = 3;
/// Byte offset of `pk[i][1]` (bit = 1 hash) within a bit's script block.
pub const SCRIPT_HASH1_OFFSET: usize = 40;

/// Two random preimages per bit (one for 0, one for 1).
pub struct SecretKey(pub [[[u8; PREIMAGE_LEN]; 2]; NUM_BITS]);

/// SHA256 of each preimage in the secret key.
pub struct PublicKey(pub [[[u8; HASH_LEN]; 2]; NUM_BITS]);

/// One revealed preimage per bit, selected by the message bit.
pub struct Signature(pub [[u8; PREIMAGE_LEN]; NUM_BITS]);

#[derive(Debug)]
pub enum LamportError {
    InvalidRange { start: usize, end: usize, max: usize },
    PreimageMismatch { bit_index: usize },
}

impl fmt::Display for LamportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange { start, end, max } => {
                write!(f, "invalid range {start}..{end} (max {max})")
            }
            Self::PreimageMismatch { bit_index } => {
                write!(f, "preimage mismatch at bit {bit_index}")
            }
        }
    }
}

impl std::error::Error for LamportError {}

fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    sha256::Hash::hash(data).to_byte_array()
}

fn get_bit(msg: &[u8; MSG_LEN], bit_index: usize) -> usize {
    let byte = msg[bit_index / 8];
    let bit = (byte >> (7 - (bit_index % 8))) & 1;
    bit as usize
}

impl SecretKey {
    pub fn random(rng: &mut (impl CryptoRng + Rng)) -> Box<SecretKey> {
        let mut sk = Box::new(SecretKey([[[0u8; PREIMAGE_LEN]; 2]; NUM_BITS]));
        for pair in sk.0.iter_mut() {
            rng.fill(&mut pair[0]);
            rng.fill(&mut pair[1]);
        }
        sk
    }

    pub fn public_key(&self) -> Box<PublicKey> {
        let mut pk = Box::new(PublicKey([[[0u8; HASH_LEN]; 2]; NUM_BITS]));
        for (i, pair) in self.0.iter().enumerate() {
            pk.0[i][0] = sha256(&pair[0]);
            pk.0[i][1] = sha256(&pair[1]);
        }
        pk
    }

    pub fn sign(&self, msg: &[u8; MSG_LEN]) -> Box<Signature> {
        let mut sig = Box::new(Signature([[0u8; PREIMAGE_LEN]; NUM_BITS]));
        for i in 0..NUM_BITS {
            let bit = get_bit(msg, i);
            sig.0[i] = self.0[i][bit];
        }
        sig
    }
}

impl PublicKey {
    pub fn verify(&self, msg: &[u8; MSG_LEN], sig: &Signature) -> bool {
        for i in 0..NUM_BITS {
            let bit = get_bit(msg, i);
            let hash = sha256(&sig.0[i]);
            if hash != self.0[i][bit] {
                return false;
            }
        }
        true
    }

    /// Recover the signed message from revealed preimages.
    /// For each bit: sha256(preimage) must match pk[i][0] (bit=0) or pk[i][1] (bit=1).
    pub fn recover_message(
        &self,
        preimages: &[[u8; PREIMAGE_LEN]; NUM_BITS],
    ) -> Result<[u8; MSG_LEN], LamportError> {
        let mut msg = [0u8; MSG_LEN];
        for i in 0..NUM_BITS {
            let hash = sha256(&preimages[i]);
            if hash == self.0[i][0] {
                // bit = 0, nothing to set
            } else if hash == self.0[i][1] {
                // bit = 1
                msg[i / 8] |= 1 << (7 - (i % 8));
            } else {
                return Err(LamportError::PreimageMismatch { bit_index: i });
            }
        }
        Ok(msg)
    }

    /// Bitcoin Script that verifies a Lamport signature for bits `start..end`.
    ///
    /// Expects witness stack to contain preimages in reverse order (last bit first)
    /// so they pop off in start-first order during execution.
    ///
    /// Per bit i:
    /// ```text
    /// OP_SHA256       (hash the preimage)
    /// OP_DUP          (duplicate the hash)
    /// <pk_i_0>        (push expected hash for bit=0)
    /// OP_EQUAL        (check match)
    /// OP_IF
    ///     OP_DROP
    /// OP_ELSE
    ///     <pk_i_1>
    ///     OP_EQUALVERIFY
    /// OP_ENDIF
    /// ```
    pub fn verification_script_for_range(
        &self,
        start: usize,
        end: usize,
    ) -> Result<ScriptBuf, LamportError> {
        if start >= end || end > NUM_BITS {
            return Err(LamportError::InvalidRange { start, end, max: NUM_BITS });
        }
        let mut builder = Builder::new();
        for i in start..end {
            builder = builder
                .push_opcode(OP_SHA256)
                .push_opcode(OP_DUP)
                .push_slice(self.0[i][0])
                .push_opcode(OP_EQUAL)
                .push_opcode(OP_IF)
                .push_opcode(OP_DROP)
                .push_opcode(OP_ELSE)
                .push_slice(self.0[i][1])
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_ENDIF);
        }
        Ok(builder.push_opcode(OP_TRUE).into_script())
    }

    /// Verification script for all bits. Only usable when the stack limit is
    /// not enforced (e.g. in tests). In production, use `verification_script_for_range`
    /// with chunks of at most `MAX_BITS_PER_CHUNK` bits.
    pub fn verification_script(&self) -> ScriptBuf {
        self.verification_script_for_range(0, NUM_BITS)
            .expect("0..NUM_BITS is always valid")
    }
}

impl Signature {
    /// Preimages for bits `start..end` as witness stack elements, reversed so
    /// the start bit is popped first during script execution.
    pub fn witness_data_for_range(
        &self,
        start: usize,
        end: usize,
    ) -> Result<Vec<Vec<u8>>, LamportError> {
        if start >= end || end > NUM_BITS {
            return Err(LamportError::InvalidRange { start, end, max: NUM_BITS });
        }
        Ok(self.0[start..end].iter().rev().map(|p| p.to_vec()).collect())
    }

    /// Witness data for all bits.
    pub fn to_witness_data(&self) -> Vec<Vec<u8>> {
        self.witness_data_for_range(0, NUM_BITS)
            .expect("0..NUM_BITS is always valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    fn random_message(rng: &mut impl Rng) -> [u8; MSG_LEN] {
        let mut msg = [0u8; MSG_LEN];
        rng.fill(&mut msg[..]);
        msg
    }

    #[test]
    fn test_keygen_sign_verify() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);
        assert!(pk.verify(&msg, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg1 = random_message(&mut rng);
        let msg2 = random_message(&mut rng);
        assert_ne!(msg1, msg2);
        let sig = sk.sign(&msg1);
        assert!(!pk.verify(&msg2, &sig));
    }

    #[test]
    fn test_verification_script_structure() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let script = pk.verification_script();
        let script_bytes = script.as_bytes();

        // Per-bit block size matches the public constant, plus a trailing OP_TRUE.
        let expected_len = NUM_BITS * SCRIPT_BYTES_PER_BIT + 1;
        assert_eq!(script_bytes.len(), expected_len);

        // Verify the hash offset constants match the actual script layout by
        // reading back pk[i][0] and pk[i][1] at the documented offsets.
        for i in 0..NUM_BITS {
            let base = i * SCRIPT_BYTES_PER_BIT;
            let hash0 = &script_bytes[base + SCRIPT_HASH0_OFFSET..base + SCRIPT_HASH0_OFFSET + HASH_LEN];
            let hash1 = &script_bytes[base + SCRIPT_HASH1_OFFSET..base + SCRIPT_HASH1_OFFSET + HASH_LEN];
            assert_eq!(hash0, pk.0[i][0]);
            assert_eq!(hash1, pk.0[i][1]);
        }
    }

    #[test]
    fn test_signature_sizes() {
        assert_eq!(std::mem::size_of::<SecretKey>(), NUM_BITS * 2 * PREIMAGE_LEN);
        assert_eq!(std::mem::size_of::<PublicKey>(), NUM_BITS * 2 * HASH_LEN);
        assert_eq!(std::mem::size_of::<Signature>(), NUM_BITS * PREIMAGE_LEN);
    }

    #[test]
    fn test_deterministic_pubkey() {
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        let sk1 = SecretKey::random(&mut rng1);
        let sk2 = SecretKey::random(&mut rng2);
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        assert_eq!(pk1.0, pk2.0);
    }

    #[test]
    fn test_witness_data_ordering() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);
        let witness = sig.to_witness_data();

        assert_eq!(witness.len(), NUM_BITS);
        // First witness element should be the last bit's preimage
        assert_eq!(witness[0].as_slice(), &sig.0[NUM_BITS - 1]);
        // Last witness element should be the first bit's preimage
        assert_eq!(witness[NUM_BITS - 1].as_slice(), &sig.0[0]);
    }

    fn run_script_with_options(script: ScriptBuf, witness: Vec<Vec<u8>>, enforce_stack_limit: bool) -> bool {
        use bitcoin::taproot::TapLeafHash;
        use bitcoin::transaction::{Transaction, TxIn, TxOut};
        use bitcoin::Amount;
        use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

        let leaf_hash = TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let prevouts = vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }];

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options {
                enforce_stack_limit,
                ..Default::default()
            },
            TxTemplate {
                tx,
                prevouts,
                input_idx: 0,
                taproot_annex_scriptleaf: Some((leaf_hash, None)),
            },
            script,
            witness,
        )
        .unwrap();

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let result = exec.result().unwrap();
        result.success
    }

    fn run_script(script: ScriptBuf, witness: Vec<Vec<u8>>) -> bool {
        run_script_with_options(script, witness, false)
    }

    #[test]
    fn test_script_execution_valid_signature() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);

        let script = pk.verification_script();
        let witness = sig.to_witness_data();

        assert!(run_script(script, witness));
    }

    #[test]
    fn test_script_execution_wrong_preimage_fails() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);

        let script = pk.verification_script();
        let mut witness = sig.to_witness_data();
        // Corrupt the first witness element (last bit's preimage)
        witness[0] = vec![0xde; PREIMAGE_LEN];

        assert!(!run_script(script, witness));
    }

    /// Verify that chunked scripts stay within the 1000 stack item limit.
    /// Splits the full 2048-bit signature into chunks of MAX_BITS_PER_CHUNK
    /// and executes each chunk with the stack limit enforced.
    #[test]
    fn test_script_execution_chunked_within_stack_limit() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);

        let num_chunks = NUM_BITS.div_ceil(MAX_BITS_PER_CHUNK);
        assert_eq!(num_chunks, 3); // 2048 / 1000 = 3 chunks

        for chunk in 0..num_chunks {
            let start = chunk * MAX_BITS_PER_CHUNK;
            let end = ((chunk + 1) * MAX_BITS_PER_CHUNK).min(NUM_BITS);

            let script = pk.verification_script_for_range(start, end).unwrap();
            let witness = sig.witness_data_for_range(start, end).unwrap();

            assert!(
                run_script_with_options(script, witness, true),
                "chunk {chunk} (bits {start}..{end}) failed with stack limit enforced"
            );
        }
    }

    #[test]
    fn test_recover_message_roundtrip() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);
        let recovered = pk.recover_message(&sig.0).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_recover_message_corrupted_preimage() {
        let mut rng = test_rng();
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let msg = random_message(&mut rng);
        let sig = sk.sign(&msg);
        let mut preimages = sig.0;
        preimages[42] = [0xde; PREIMAGE_LEN];
        let result = pk.recover_message(&preimages);
        assert!(result.is_err());
        match result.unwrap_err() {
            LamportError::PreimageMismatch { bit_index } => assert_eq!(bit_index, 42),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_get_bit() {
        let mut msg = [0u8; MSG_LEN];
        msg[0] = 0b10110001;
        assert_eq!(get_bit(&msg, 0), 1);
        assert_eq!(get_bit(&msg, 1), 0);
        assert_eq!(get_bit(&msg, 2), 1);
        assert_eq!(get_bit(&msg, 3), 1);
        assert_eq!(get_bit(&msg, 4), 0);
        assert_eq!(get_bit(&msg, 5), 0);
        assert_eq!(get_bit(&msg, 6), 0);
        assert_eq!(get_bit(&msg, 7), 1);
    }
}
