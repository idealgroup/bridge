use bitcoin::key::UntweakedPublicKey as XOnlyPublicKey;
use bitcoin::transaction::Transaction;

use bridge::engine::Proof;
use bridge::params::Params;
use bridge::BridgeError;

/// Script layout constants used to parse kickoff tx witnesses from on-chain
/// and recover the Lamport signatures (operator pubkey + proof preimages).
///
/// Byte layout of the fanout leaf script prefix (before the Lamport verification block):
///
/// ```text
/// offset  bytes  meaning
/// 0       1      OP_PUSHBYTES_32
/// 1..33   32     operator x-only pubkey
/// 33      1      OP_CHECKSIGVERIFY
/// ```
///
/// See `bridge::scripts::fanout_leaf_script`. The Lamport verification block starts
/// immediately after at offset [`SCRIPT_FANOUT_LEAF_PREFIX_LEN`].
const SCRIPT_FANOUT_LEAF_PREFIX_LEN: usize = 1 + 32 + 1;
const SCRIPT_OPERATOR_PUBKEY_OFFSET: usize = 1;

/// Serialized size (in bytes) of the per-bit verification block in a Lamport
/// verification script. Layout: OP_SHA256 + OP_DUP + push32(hash0) + OP_EQUAL
/// + OP_IF + OP_DROP + OP_ELSE + push32(hash1) + OP_EQUALVERIFY + OP_ENDIF.
const SCRIPT_BYTES_PER_BIT: usize = 74;
/// Byte offset of the bit=0 hash within a per-bit script block.
const SCRIPT_HASH0_OFFSET: usize = 3;
/// Byte offset of the bit=1 hash within a per-bit script block.
const SCRIPT_HASH1_OFFSET: usize = 40;

/// Data extracted from a kickoff transaction's witnesses.
pub struct KickoffData {
    pub operator_pubkey: XOnlyPublicKey,
    pub proof: Proof,
    pub lamport_pk: Box<lamport::PublicKey>,
}

/// Extract proof, operator pubkey, and Lamport PK from a kickoff tx.
/// Parses leaf scripts from witness data — no external info needed.
pub fn extract_proof_from_kickoff(
    tx: &Transaction,
    params: &Params,
) -> Result<KickoffData, BridgeError> {
    let num_chunks = params.lamport_chunks_per_slot;
    if tx.input.len() != num_chunks {
        return Err(BridgeError::WitnessParse(format!(
            "expected {} inputs, got {}",
            num_chunks,
            tx.input.len()
        )));
    }

    let mut full_pk = Box::new(lamport::PublicKey(
        [[[0u8; lamport::HASH_LEN]; 2]; lamport::NUM_BITS],
    ));
    let mut all_preimages = [[0u8; lamport::PREIMAGE_LEN]; lamport::NUM_BITS];
    let mut operator_pubkey: Option<XOnlyPublicKey> = None;

    for chunk in 0..num_chunks {
        let (start, end) = params.lamport_chunk_range(chunk);
        let num_bits = end - start;
        let witness = &tx.input[chunk].witness;
        let wit_len = witness.len();

        // Witness layout: [preimages_reversed...] [sig] [leaf_script] [control_block]
        // So leaf_script is witness[wit_len - 2]
        if wit_len < 3 {
            return Err(BridgeError::WitnessParse(format!(
                "input {} witness too short ({})",
                chunk, wit_len
            )));
        }

        let num_preimages = num_bits;
        let expected_wit_len = num_preimages + 3; // preimages + sig + script + control_block
        if wit_len != expected_wit_len {
            return Err(BridgeError::WitnessParse(format!(
                "input {} witness len {}, expected {}",
                chunk, wit_len, expected_wit_len
            )));
        }

        let leaf_script = witness[wit_len - 2].to_vec();

        // Extract operator pubkey from leaf script prefix (see SCRIPT_FANOUT_LEAF_PREFIX_LEN).
        if leaf_script.len() < SCRIPT_FANOUT_LEAF_PREFIX_LEN {
            return Err(BridgeError::WitnessParse(
                "leaf script too short for operator pubkey".into(),
            ));
        }
        if leaf_script[0] != 0x20 {
            return Err(BridgeError::WitnessParse(format!(
                "expected OP_PUSHBYTES_32 (0x20) at script[0], got 0x{:02x}",
                leaf_script[0]
            )));
        }
        let chunk_op_pk = XOnlyPublicKey::from_slice(
            &leaf_script[SCRIPT_OPERATOR_PUBKEY_OFFSET..SCRIPT_OPERATOR_PUBKEY_OFFSET + 32],
        )
        .map_err(|e| BridgeError::WitnessParse(format!("operator pubkey: {e}")))?;
        match operator_pubkey {
            None => operator_pubkey = Some(chunk_op_pk),
            Some(ref prev) => {
                if *prev != chunk_op_pk {
                    return Err(BridgeError::WitnessParse(
                        "operator pubkey mismatch across chunks".into(),
                    ));
                }
            }
        }

        // Extract Lamport PK hashes from the leaf script. The Lamport verification
        // block starts immediately after the fanout leaf prefix; see the lamport
        // crate's SCRIPT_* constants for the per-bit byte layout.
        for bit_idx in 0..num_bits {
            let global_bit = start + bit_idx;
            let base = SCRIPT_FANOUT_LEAF_PREFIX_LEN + bit_idx * SCRIPT_BYTES_PER_BIT;
            if base + SCRIPT_BYTES_PER_BIT > leaf_script.len() {
                return Err(BridgeError::WitnessParse(format!(
                    "leaf script too short for bit {}",
                    global_bit
                )));
            }
            let hash0_start = base + SCRIPT_HASH0_OFFSET;
            let hash1_start = base + SCRIPT_HASH1_OFFSET;
            full_pk.0[global_bit][0]
                .copy_from_slice(&leaf_script[hash0_start..hash0_start + lamport::HASH_LEN]);
            full_pk.0[global_bit][1]
                .copy_from_slice(&leaf_script[hash1_start..hash1_start + lamport::HASH_LEN]);
        }

        // Extract preimages from witness[0..num_preimages], they are in reversed order
        for i in 0..num_preimages {
            let preimage = witness[i].to_vec();
            if preimage.len() != lamport::PREIMAGE_LEN {
                return Err(BridgeError::WitnessParse(format!(
                    "preimage {} wrong length {} (expected {})",
                    i,
                    preimage.len(),
                    lamport::PREIMAGE_LEN
                )));
            }
            // Witness is reversed: witness[0] is the last bit's preimage
            let global_bit = start + (num_preimages - 1 - i);
            all_preimages[global_bit].copy_from_slice(&preimage);
        }
    }

    let operator_pubkey = operator_pubkey
        .ok_or_else(|| BridgeError::WitnessParse("no operator pubkey found".into()))?;

    // Recover the message (proof) from preimages + PK
    let proof_msg = full_pk
        .recover_message(&all_preimages)
        .map_err(|e| BridgeError::WitnessParse(format!("recover_message: {e}")))?;

    Ok(KickoffData {
        operator_pubkey,
        proof: proof_msg,
        lamport_pk: full_pk,
    })
}
