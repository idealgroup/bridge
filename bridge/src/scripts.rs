use bitcoin::key::UntweakedPublicKey as XOnlyPublicKey;
use bitcoin::opcodes::all::*;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::blockdata::transaction::Sequence;
use bitcoin::secp256k1::Secp256k1;

use bitcoin::Amount;

use crate::BridgeError;

/// P2A (Pay-to-Anchor) dust threshold: 240 sats.
pub const P2A_DUST: Amount = Amount::from_sat(240);

/// P2A (Pay-to-Anchor) scriptPubKey: `OP_1 <0x4e73>`.
/// Anyone-can-spend output for CPFP fee bumping on presigned transactions.
pub fn p2a_script() -> ScriptBuf {
    use bitcoin::blockdata::script::witness_program::WitnessProgram;
    use bitcoin::blockdata::script::witness_version::WitnessVersion;
    let program = WitnessProgram::new(WitnessVersion::V1, &[0x4e, 0x73])
        .expect("valid 2-byte witness v1 program");
    ScriptBuf::new_witness_program(&program)
}

/// BIP-341 unspendable internal key (NUMS point).
/// H = lift_x(0x0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
/// This is the "nothing up my sleeve" point with no known discrete log.
pub fn unspendable_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
        0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
        0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ]).expect("valid NUMS point")
}

/// Request output (P2TR): committee key-spend + cancel script leaf.
///
/// Cancel leaf: `<deposit_timeout> OP_CSV OP_DROP OP_SHA256 <deposit_secret_hash> OP_EQUALVERIFY <depositor_pubkey> OP_CHECKSIG`
pub fn request_spend_info(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    committee_pubkey: XOnlyPublicKey,
    depositor_pubkey: XOnlyPublicKey,
    deposit_secret_hash: [u8; 32],
    deposit_timeout: Sequence,
) -> Result<TaprootSpendInfo, BridgeError> {
    let cancel_script = Builder::new()
        .push_sequence(deposit_timeout)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_SHA256)
        .push_slice(deposit_secret_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&depositor_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    TaprootBuilder::new()
        .add_leaf(0, cancel_script)
        .map_err(|e| BridgeError::TaprootBuilder(format!("{e:?}")))?
        .finalize(secp, committee_pubkey)
        .map_err(|e| BridgeError::TaprootBuilder(format!("{e:?}")))
}

/// Fanout leaf output (P2TR, one per Lamport chunk).
///
/// Script leaf: `<operator_pubkey> OP_CHECKSIGVERIFY <lamport_verification_for_chunk>`
pub fn fanout_leaf_spend_info(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    operator_pubkey: XOnlyPublicKey,
    lamport_pk: &lamport::PublicKey,
    chunk_start: usize,
    chunk_end: usize,
) -> Result<TaprootSpendInfo, BridgeError> {
    let lamport_script = lamport_pk
        .verification_script_for_range(chunk_start, chunk_end)
        .map_err(|e| BridgeError::Signing(format!("lamport: {e}")))?;

    let script = Builder::new()
        .push_x_only_key(&operator_pubkey)
        .push_opcode(OP_CHECKSIGVERIFY)
        .into_script();

    // Concatenate: operator checksig + lamport verification
    let full_script = ScriptBuf::from(
        [script.as_bytes(), lamport_script.as_bytes()].concat(),
    );

    TaprootBuilder::new()
        .add_leaf(0, full_script)
        .map_err(|e| BridgeError::TaprootBuilder(format!("{e:?}")))?
        .finalize(secp, unspendable_internal_key())
        .map_err(|e| BridgeError::TaprootBuilder(format!("{e:?}")))
}

/// Kickoff connector output (P2TR):
/// - Key-spend: operator (for withdraw path — timelock enforced by nSequence
///   committed in the committee's presigned withdrawTx input0)
/// - Script leaf (disprove): `OP_SHA256 <disprove_secret_hash> OP_EQUAL`
pub fn connector_spend_info(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    operator_pubkey: XOnlyPublicKey,
    disprove_secret_hash: [u8; 32],
) -> Result<TaprootSpendInfo, BridgeError> {
    let disprove_script = Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(disprove_secret_hash)
        .push_opcode(OP_EQUAL)
        .into_script();

    TaprootBuilder::new()
        .add_leaf(0, disprove_script)
        .map_err(|e| BridgeError::TaprootBuilder(format!("{e:?}")))?
        .finalize(secp, operator_pubkey)
        .map_err(|e| BridgeError::TaprootBuilder(format!("{e:?}")))
}

/// Cancel script for spending a request output via the script path.
pub fn cancel_script(
    depositor_pubkey: XOnlyPublicKey,
    deposit_secret_hash: [u8; 32],
    deposit_timeout: Sequence,
) -> ScriptBuf {
    Builder::new()
        .push_sequence(deposit_timeout)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_SHA256)
        .push_slice(deposit_secret_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&depositor_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Disprove leaf script (spending a connector via hash preimage).
pub fn disprove_script(disprove_secret_hash: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(disprove_secret_hash)
        .push_opcode(OP_EQUAL)
        .into_script()
}

/// Fanout leaf script: operator checksig + lamport verification for a chunk.
pub fn fanout_leaf_script(
    operator_pubkey: XOnlyPublicKey,
    lamport_pk: &lamport::PublicKey,
    chunk_start: usize,
    chunk_end: usize,
) -> Result<ScriptBuf, BridgeError> {
    let lamport_script = lamport_pk
        .verification_script_for_range(chunk_start, chunk_end)
        .map_err(|e| BridgeError::Signing(format!("lamport: {e}")))?;
    let prefix = Builder::new()
        .push_x_only_key(&operator_pubkey)
        .push_opcode(OP_CHECKSIGVERIFY)
        .into_script();
    Ok(ScriptBuf::from([prefix.as_bytes(), lamport_script.as_bytes()].concat()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::SecretKey;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand::Rng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    fn random_keypair(rng: &mut impl Rng, secp: &Secp256k1<bitcoin::secp256k1::All>) -> Keypair {
        let mut bytes = [0u8; 32];
        loop {
            rng.fill(&mut bytes);
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                return Keypair::from_secret_key(secp, &sk);
            }
        }
    }

    #[test]
    fn test_unspendable_key() {
        let key = unspendable_internal_key();
        assert_eq!(key.serialize().len(), 32);
    }

    #[test]
    fn test_request_spend_info_builds() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let committee = random_keypair(&mut rng, &secp);
        let depositor = random_keypair(&mut rng, &secp);
        let (cpk, _) = committee.x_only_public_key();
        let (dpk, _) = depositor.x_only_public_key();
        let hash = [0xab; 32];
        let timeout = Sequence::from_height(5);

        let info = request_spend_info(&secp, cpk, dpk, hash, timeout).unwrap();
        assert_eq!(info.output_key().serialize().len(), 32);
    }

    #[test]
    fn test_connector_spend_info_builds() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let operator = random_keypair(&mut rng, &secp);
        let (opk, _) = operator.x_only_public_key();
        let hash = [0xcd; 32];

        let info = connector_spend_info(&secp, opk, hash).unwrap();
        assert_eq!(info.output_key().serialize().len(), 32);
    }

    #[test]
    fn test_fanout_leaf_spend_info_builds() {
        let secp = Secp256k1::new();
        let mut rng = test_rng();
        let operator = random_keypair(&mut rng, &secp);
        let (opk, _) = operator.x_only_public_key();
        let sk = lamport::SecretKey::random(&mut rng);
        let pk = sk.public_key();

        let info = fanout_leaf_spend_info(&secp, opk, &pk, 0, 998).unwrap();
        assert_eq!(info.output_key().serialize().len(), 32);
    }
}
