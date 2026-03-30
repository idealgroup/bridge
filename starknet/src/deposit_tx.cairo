// Reconstruct the deterministic depositTx and compute its BIP341 sighash.
//
// The depositTx is fully deterministic given:
//   - requestTx txid (prevout)
//   - committee pubkey (output address)
//   - deposit_size (output amount)
//
// depositTx structure:
//   version: 2
//   inputs: 1 (request_txid:0, empty script, seq 0xFFFFFFFD)
//   outputs: 1 (deposit_size sats, P2TR key-only to committee)
//   locktime: 0

use alexandria_btc::taproot::{tweak_public_key, u256_to_32_bytes_be};
use crate::bip341::taproot_sighash;

const TX_VERSION: u32 = 2;
const LOCKTIME: u32 = 0;
const SEQUENCE_RBF: u32 = 0xFFFFFFFD;

/// Build the P2TR scriptPubKey for a key-only spend (no script tree).
/// Format: OP_1 (0x51) || OP_PUSHBYTES_32 (0x20) || tweaked_x_only_pubkey (32 bytes)
fn build_p2tr_script_pubkey(committee_pubkey: u256) -> ByteArray {
    // Tweak with no merkle root (key-path only)
    let tweaked = tweak_public_key(committee_pubkey, Option::None)
        .expect('invalid committee pubkey');
    let tweaked_bytes = u256_to_32_bytes_be(tweaked.output_key);

    let mut spk: ByteArray = "";
    spk.append_byte(0x51); // OP_1
    spk.append_byte(0x20); // push 32 bytes
    let mut i: u32 = 0;
    while i < 32 {
        spk.append_byte(*tweaked_bytes.at(i));
        i += 1;
    };
    spk
}

/// Compute the BIP341 sighash for the depositTx.
///
/// The committee signs this sighash. The contract verifies the signature
/// against this sighash to confirm the committee approved the deposit.
///
/// Arguments:
/// - `request_txid`: txid of the requestTx (internal byte order, LE from hash)
/// - `request_output0_amount`: the amount of requestTx output 0 (the prevout being spent)
/// - `request_output0_script_pubkey`: the scriptPubKey of requestTx output 0
/// - `committee_pubkey`: the committee's x-only public key (untweaked)
pub fn compute_deposit_sighash(
    request_txid: u256,
    request_output0_amount: u64,
    request_output0_script_pubkey: @ByteArray,
    committee_pubkey: u256,
    deposit_output_amount: u64,
) -> u256 {
    let output_script_pubkey = build_p2tr_script_pubkey(committee_pubkey);

    taproot_sighash(
        TX_VERSION,
        LOCKTIME,
        request_txid,        // prevout txid
        0,                   // prevout vout (always output 0 of requestTx)
        request_output0_amount,
        request_output0_script_pubkey,
        SEQUENCE_RBF,
        deposit_output_amount,
        @output_script_pubkey,
        0x00,                // spend_type: key-path
        0,                   // input_index: 0
    )
}
