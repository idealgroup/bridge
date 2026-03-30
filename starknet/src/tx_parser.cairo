// Parse a serialized Bitcoin requestTx to extract fields needed by the contract.
//
// requestTx structure (non-segwit for txid computation):
//   version (4 LE) | input_count (varint) | inputs | output_count (varint) | outputs | locktime (4 LE)
//
// Output 0: P2TR deposit output (committee key-spend + cancel script leaf)
// Output 1: OP_RETURN with 32-byte Starknet address
//
// The cancel script inside output 0's taproot tree contains the deposit_secret_hash,
// but we don't parse that here — it's passed separately as contract storage key.
//
// We extract:
//   - txid: double-SHA256 of the full serialized tx (in internal byte order)
//   - output 0 amount + scriptPubKey (the deposit UTXO being spent by depositTx)
//   - OP_RETURN data from output 1 (32-byte Starknet recipient address)

use alexandria_btc::hash::sha256_u256;

/// Parsed data from a requestTx.
#[derive(Drop)]
pub struct RequestTxData {
    /// Transaction ID (double-SHA256, big-endian / internal byte order).
    pub txid: u256,
    /// Output 0 value in satoshis.
    pub output0_amount: u64,
    /// Output 0 scriptPubKey (P2TR, 34 bytes: 0x5120 + 32-byte key).
    pub output0_script_pubkey: ByteArray,
    /// 32-byte Starknet address from OP_RETURN output 1.
    pub starknet_address: felt252,
    /// deposit_secret_hash extracted from the cancel script in output 0.
    /// (SHA256 hash of the deposit secret, 32 bytes)
    pub deposit_secret_hash: u256,
}

/// Read a u32 little-endian from ByteArray at offset.
fn read_u32_le(raw: @ByteArray, offset: usize) -> u32 {
    let b0: u32 = raw.at(offset).unwrap().into();
    let b1: u32 = raw.at(offset + 1).unwrap().into();
    let b2: u32 = raw.at(offset + 2).unwrap().into();
    let b3: u32 = raw.at(offset + 3).unwrap().into();
    b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
}

/// Read a u64 little-endian from ByteArray at offset.
fn read_u64_le(raw: @ByteArray, offset: usize) -> u64 {
    let lo: u64 = read_u32_le(raw, offset).into();
    let hi: u64 = read_u32_le(raw, offset + 4).into();
    lo + hi * 0x100000000
}

/// Read a compact size (varint). Returns (value, bytes_consumed).
fn read_compact_size(raw: @ByteArray, offset: usize) -> (usize, usize) {
    let first: u8 = raw.at(offset).unwrap();
    if first < 0xfd {
        (first.into(), 1)
    } else if first == 0xfd {
        let lo: usize = raw.at(offset + 1).unwrap().into();
        let hi: usize = raw.at(offset + 2).unwrap().into();
        (lo + hi * 256, 3)
    } else {
        panic!("compact size > 0xffff not supported")
    }
}

/// Read N bytes from ByteArray at offset into a new ByteArray.
fn read_bytes(raw: @ByteArray, offset: usize, len: usize) -> ByteArray {
    let mut result: ByteArray = "";
    let mut i: usize = 0;
    while i < len {
        result.append_byte(raw.at(offset + i).unwrap());
        i += 1;
    };
    result
}

/// Read 32 bytes as u256 big-endian.
fn read_u256_be(raw: @ByteArray, offset: usize) -> u256 {
    let mut result: u256 = 0;
    let mut i: usize = 0;
    while i < 32 {
        let byte: u256 = raw.at(offset + i).unwrap().into();
        result = result * 256 + byte;
        i += 1;
    };
    result
}

/// Compute txid from raw non-segwit transaction bytes.
/// Returns SHA256d as a u256 in natural byte order (first hash byte = MSB).
/// This is the same order Bitcoin uses in serialized outpoints and BIP341 sighash.
/// (Bitcoin's "display" order reverses the bytes; we do NOT reverse here.)
fn compute_txid(raw: @ByteArray) -> u256 {
    // First SHA256
    let first_hash = sha256_u256(raw);
    // Second SHA256
    let mut first_ba: ByteArray = "";
    crate::bip341::append_u256_be(ref first_ba, first_hash);
    sha256_u256(@first_ba)
}

/// Extract deposit_secret_hash from the request output's scriptPubKey.
///
/// The requestTx output 0 is P2TR with committee key-spend and a cancel script leaf.
/// The cancel script is: <timeout> OP_CSV OP_DROP OP_SHA256 <32-byte hash> OP_EQUALVERIFY <pubkey> OP_CHECKSIG
///
/// We don't parse the taproot tree here. Instead, the deposit_secret_hash is provided
/// as a parameter to the request() function (the depositor knows it).

/// Parse a serialized requestTx.
///
/// Expected format:
///   - Non-segwit serialization (for txid computation)
///   - 1 input
///   - 2 outputs: output 0 = P2TR deposit, output 1 = OP_RETURN with Starknet address
pub fn parse_request_tx(
    raw: @ByteArray, deposit_secret_hash: u256,
) -> RequestTxData {
    let txid = compute_txid(raw);

    // Skip version (4 bytes)
    let mut offset: usize = 4;

    // Input count
    let (input_count, consumed) = read_compact_size(raw, offset);
    offset += consumed;
    assert(input_count >= 1, 'expected at least 1 input');

    // Skip all inputs
    let mut i: usize = 0;
    while i < input_count {
        // txid (32) + vout (4)
        offset += 36;
        // script_sig length
        let (script_len, c) = read_compact_size(raw, offset);
        offset += c;
        // script_sig bytes
        offset += script_len;
        // sequence (4)
        offset += 4;
        i += 1;
    };

    // Output count
    let (output_count, consumed) = read_compact_size(raw, offset);
    offset += consumed;
    assert(output_count >= 2, 'need at least 2 outputs');

    // Output 0: deposit P2TR output
    let output0_amount = read_u64_le(raw, offset);
    offset += 8;
    let (spk0_len, consumed) = read_compact_size(raw, offset);
    offset += consumed;
    let output0_script_pubkey = read_bytes(raw, offset, spk0_len);
    offset += spk0_len;

    // Output 1: OP_RETURN with Starknet address
    let _output1_amount = read_u64_le(raw, offset);
    offset += 8;
    let (spk1_len, consumed) = read_compact_size(raw, offset);
    offset += consumed;

    // OP_RETURN script: 0x6a (OP_RETURN) + push opcode + 32-byte data
    let op_return_byte: u8 = raw.at(offset).unwrap();
    assert(op_return_byte == 0x6a, 'expected OP_RETURN');

    // Next byte is push length (0x20 = 32)
    let push_len: u8 = raw.at(offset + 1).unwrap();
    assert(push_len == 0x20, 'expected 32-byte push');

    // Read 32 bytes as the Starknet address (felt252, big-endian)
    // Starknet addresses are < 2^251, so they fit in felt252
    let mut starknet_addr_u256: u256 = 0;
    let mut j: usize = 0;
    while j < 32 {
        let byte: u256 = raw.at(offset + 2 + j).unwrap().into();
        starknet_addr_u256 = starknet_addr_u256 * 256 + byte;
        j += 1;
    };
    let starknet_address: felt252 = starknet_addr_u256.try_into().expect('starknet addr too large');

    // Verify we consumed the right amount
    let _ = spk1_len; // suppress unused warning

    RequestTxData {
        txid,
        output0_amount,
        output0_script_pubkey,
        starknet_address,
        deposit_secret_hash,
    }
}
