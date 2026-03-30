// BIP341 sighash computation for SIGHASH_DEFAULT (= SIGHASH_ALL for taproot key-spend).
//
// Uses alexandria_btc::taproot::tagged_hash_u256 for tagged hashing and
// alexandria_btc::hash::sha256_u256 for plain SHA256.

use alexandria_btc::hash::sha256_u256;
use alexandria_btc::taproot::tagged_hash_u256;

/// Append a u256 (32 bytes, big-endian) to a ByteArray.
pub fn append_u256_be(ref ba: ByteArray, value: u256) {
    // high 128 bits (16 bytes)
    let mut hi = value.high;
    let mut hi_bytes: Array<u8> = array![];
    let mut i: u32 = 0;
    while i < 16 {
        hi_bytes.append((hi % 256).try_into().unwrap());
        hi = hi / 256;
        i += 1;
    };
    let mut j: u32 = 16;
    while j > 0 {
        j -= 1;
        ba.append_byte(*hi_bytes.at(j));
    };
    // low 128 bits (16 bytes)
    let mut lo = value.low;
    let mut lo_bytes: Array<u8> = array![];
    i = 0;
    while i < 16 {
        lo_bytes.append((lo % 256).try_into().unwrap());
        lo = lo / 256;
        i += 1;
    };
    j = 16;
    while j > 0 {
        j -= 1;
        ba.append_byte(*lo_bytes.at(j));
    };
}

/// Append a u64 as 4 little-endian bytes (truncated to u32).
fn append_u32_le(ref ba: ByteArray, value: u32) {
    ba.append_byte((value % 256).try_into().unwrap());
    ba.append_byte(((value / 256) % 256).try_into().unwrap());
    ba.append_byte(((value / 65536) % 256).try_into().unwrap());
    ba.append_byte(((value / 16777216) % 256).try_into().unwrap());
}

/// Append a u64 as 8 little-endian bytes.
fn append_u64_le(ref ba: ByteArray, value: u64) {
    let mut v = value;
    let mut i: u32 = 0;
    while i < 8 {
        ba.append_byte((v % 256).try_into().unwrap());
        v = v / 256;
        i += 1;
    };
}

/// Compute BIP341 taproot key-spend sighash (SIGHASH_DEFAULT = SIGHASH_ALL equivalent).
///
/// This implements the exact sighash algorithm from BIP341 for a single-input,
/// single-output transaction (our depositTx structure).
///
/// Arguments:
/// - `version`: transaction version (u32 LE)
/// - `locktime`: transaction locktime (u32 LE)
/// - `prevout_txid`: the txid of the input's previous outpoint (u256, internal byte order = LE)
/// - `prevout_vout`: the vout of the input's previous outpoint (u32 LE)
/// - `prevout_amount`: the amount of the previous output (u64 sats LE)
/// - `prevout_script_pubkey`: the scriptPubKey of the previous output
/// - `sequence`: the nSequence of the input (u32 LE)
/// - `output_amount`: the output amount (u64 sats LE)
/// - `output_script_pubkey`: the output's scriptPubKey
/// - `spend_type`: 0x00 for key-path spend
/// - `input_index`: which input is being signed (u32 LE)
///
/// For our depositTx (1 input, 1 output), input_index is always 0.
pub fn taproot_sighash(
    version: u32,
    locktime: u32,
    prevout_txid: u256,
    prevout_vout: u32,
    prevout_amount: u64,
    prevout_script_pubkey: @ByteArray,
    sequence: u32,
    output_amount: u64,
    output_script_pubkey: @ByteArray,
    spend_type: u8,
    input_index: u32,
) -> u256 {
    // sha_prevouts = SHA256(outpoint0)
    // outpoint = txid (32 bytes LE) || vout (4 bytes LE)
    let mut prevouts_preimage: ByteArray = "";
    append_u256_be(ref prevouts_preimage, prevout_txid);
    append_u32_le(ref prevouts_preimage, prevout_vout);
    let sha_prevouts = sha256_u256(@prevouts_preimage);

    // sha_amounts = SHA256(amount0 as u64 LE)
    let mut amounts_preimage: ByteArray = "";
    append_u64_le(ref amounts_preimage, prevout_amount);
    let sha_amounts = sha256_u256(@amounts_preimage);

    // sha_scriptpubkeys = SHA256(compact_size(len) || scriptpubkey)
    let mut scriptpubkeys_preimage: ByteArray = "";
    let spk_len: u8 = prevout_script_pubkey.len().try_into().unwrap();
    scriptpubkeys_preimage.append_byte(spk_len);
    scriptpubkeys_preimage.append(prevout_script_pubkey);
    let sha_scriptpubkeys = sha256_u256(@scriptpubkeys_preimage);

    // sha_sequences = SHA256(sequence0 as u32 LE)
    let mut sequences_preimage: ByteArray = "";
    append_u32_le(ref sequences_preimage, sequence);
    let sha_sequences = sha256_u256(@sequences_preimage);

    // sha_outputs = SHA256(output0)
    // output = amount (8 LE) || compact_size(scriptpubkey.len) || scriptpubkey
    let mut outputs_preimage: ByteArray = "";
    append_u64_le(ref outputs_preimage, output_amount);
    let out_spk_len: u8 = output_script_pubkey.len().try_into().unwrap();
    outputs_preimage.append_byte(out_spk_len);
    outputs_preimage.append(output_script_pubkey);
    let sha_outputs = sha256_u256(@outputs_preimage);

    // Epoch (0x00)
    let mut sighash_preimage: ByteArray = "";
    sighash_preimage.append_byte(0x00);

    // hash_type (0x00 = SIGHASH_DEFAULT)
    sighash_preimage.append_byte(0x00);

    // version (4 bytes LE)
    append_u32_le(ref sighash_preimage, version);

    // locktime (4 bytes LE)
    append_u32_le(ref sighash_preimage, locktime);

    // sha_prevouts (32 bytes)
    append_u256_be(ref sighash_preimage, sha_prevouts);

    // sha_amounts (32 bytes)
    append_u256_be(ref sighash_preimage, sha_amounts);

    // sha_scriptpubkeys (32 bytes)
    append_u256_be(ref sighash_preimage, sha_scriptpubkeys);

    // sha_sequences (32 bytes)
    append_u256_be(ref sighash_preimage, sha_sequences);

    // sha_outputs (32 bytes)
    append_u256_be(ref sighash_preimage, sha_outputs);

    // spend_type (1 byte)
    sighash_preimage.append_byte(spend_type);

    // input_index (4 bytes LE)
    append_u32_le(ref sighash_preimage, input_index);

    tagged_hash_u256("TapSighash", @sighash_preimage)
}
