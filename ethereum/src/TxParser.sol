// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TxParser — parse a Bitcoin non-segwit transaction
/// @notice Extracts fields from a serialized requestTx:
///         - txid (double-sha256 of the full buffer, internal byte order)
///         - output 0 amount + scriptPubKey (expected P2TR, 34 bytes)
///         - output 1 OP_RETURN recipient (20-byte Ethereum address)
library TxParser {
    struct RequestTxData {
        bytes32 txid;
        uint64 output0Amount;
        bytes output0ScriptPubkey;
        address recipient;
    }

    /// @notice Read a u32 little-endian from `raw` at `offset`.
    function readU32Le(bytes calldata raw, uint256 offset) internal pure returns (uint32) {
        return uint32(uint8(raw[offset]))
            | (uint32(uint8(raw[offset + 1])) << 8)
            | (uint32(uint8(raw[offset + 2])) << 16)
            | (uint32(uint8(raw[offset + 3])) << 24);
    }

    /// @notice Read a u64 little-endian from `raw` at `offset`.
    function readU64Le(bytes calldata raw, uint256 offset) internal pure returns (uint64) {
        uint64 lo = uint64(readU32Le(raw, offset));
        uint64 hi = uint64(readU32Le(raw, offset + 4));
        return lo | (hi << 32);
    }

    /// @notice Read a compact size (varint). Returns (value, bytes_consumed).
    function readCompactSize(bytes calldata raw, uint256 offset)
        internal
        pure
        returns (uint256 value, uint256 consumed)
    {
        uint8 first = uint8(raw[offset]);
        if (first < 0xfd) {
            return (uint256(first), 1);
        } else if (first == 0xfd) {
            uint256 lo = uint256(uint8(raw[offset + 1]));
            uint256 hi = uint256(uint8(raw[offset + 2]));
            return (lo | (hi << 8), 3);
        } else {
            revert("compact size > 0xffff not supported");
        }
    }

    /// @notice Compute txid from raw non-segwit transaction bytes. Returns
    ///         sha256d in natural byte order (first hash byte = MSB). Matches
    ///         the order used by Bitcoin in outpoints and BIP341 sighash.
    function computeTxid(bytes calldata raw) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(raw)));
    }

    /// @notice Parse a serialized requestTx.
    ///
    /// Expected format:
    /// - Non-segwit serialization (for txid computation)
    /// - >= 1 input
    /// - >= 2 outputs: output 0 = P2TR deposit, output 1 = OP_RETURN with 20-byte address
    function parseRequestTx(bytes calldata raw) internal pure returns (RequestTxData memory out) {
        out.txid = computeTxid(raw);

        // Skip version (4 bytes)
        uint256 offset = 4;

        // Input count
        (uint256 inputCount, uint256 consumed) = readCompactSize(raw, offset);
        offset += consumed;
        require(inputCount >= 1, "expected at least 1 input");

        // Skip all inputs
        for (uint256 i = 0; i < inputCount; i++) {
            // txid (32) + vout (4)
            offset += 36;
            (uint256 scriptLen, uint256 c) = readCompactSize(raw, offset);
            offset += c;
            offset += scriptLen;
            // sequence (4)
            offset += 4;
        }

        // Output count
        (uint256 outputCount, uint256 consumed2) = readCompactSize(raw, offset);
        offset += consumed2;
        require(outputCount >= 2, "need at least 2 outputs");

        // Output 0: deposit P2TR output
        out.output0Amount = readU64Le(raw, offset);
        offset += 8;
        (uint256 spk0Len, uint256 consumed3) = readCompactSize(raw, offset);
        offset += consumed3;
        out.output0ScriptPubkey = raw[offset:offset + spk0Len];
        offset += spk0Len;

        // Output 1: OP_RETURN with 20-byte Ethereum address
        // Skip output 1 amount (8 bytes)
        offset += 8;
        (uint256 spk1Len, uint256 consumed4) = readCompactSize(raw, offset);
        offset += consumed4;

        // OP_RETURN script: 0x6a (OP_RETURN) + push opcode (0x14 = 20) + 20-byte data
        require(spk1Len == 22, "bad OP_RETURN length");
        require(uint8(raw[offset]) == 0x6a, "expected OP_RETURN");
        require(uint8(raw[offset + 1]) == 0x14, "expected 20-byte push");

        // Read 20 bytes as the Ethereum address (big-endian)
        uint160 addr = 0;
        for (uint256 j = 0; j < 20; j++) {
            addr = (addr << 8) | uint160(uint8(raw[offset + 2 + j]));
        }
        out.recipient = address(addr);
    }
}
