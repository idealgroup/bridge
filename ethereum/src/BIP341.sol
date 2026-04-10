// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BIP341 taproot sighash computation (SIGHASH_DEFAULT key-path spend).
/// @notice Computes the BIP341 taproot key-spend sighash for a single-input,
///         single-output transaction (matching the depositTx structure).
library BIP341 {
    /// @notice Tagged hash per BIP340/BIP341: sha256(sha256(tag) || sha256(tag) || msg)
    function taggedHash(string memory tag, bytes memory data) internal pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, data));
    }

    /// @notice Little-endian u32 encoding (4 bytes).
    function u32Le(uint32 v) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(uint8(v)),
            bytes1(uint8(v >> 8)),
            bytes1(uint8(v >> 16)),
            bytes1(uint8(v >> 24))
        );
    }

    /// @notice Little-endian u64 encoding (8 bytes).
    function u64Le(uint64 v) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(uint8(v)),
            bytes1(uint8(v >> 8)),
            bytes1(uint8(v >> 16)),
            bytes1(uint8(v >> 24)),
            bytes1(uint8(v >> 32)),
            bytes1(uint8(v >> 40)),
            bytes1(uint8(v >> 48)),
            bytes1(uint8(v >> 56))
        );
    }

    /// @notice Compute BIP341 taproot key-spend sighash (SIGHASH_DEFAULT).
    ///
    /// Implements the exact sighash algorithm from BIP341 for a single-input,
    /// single-output transaction (our depositTx structure).
    ///
    /// @param version            transaction version
    /// @param locktime           transaction locktime
    /// @param prevoutTxid        txid of the input's previous outpoint (internal byte order)
    /// @param prevoutVout        vout of the input's previous outpoint
    /// @param prevoutAmount      amount of the previous output (sats)
    /// @param prevoutScriptPubkey  scriptPubKey of the previous output
    /// @param sequence           nSequence of the input
    /// @param outputAmount       output amount (sats)
    /// @param outputScriptPubkey scriptPubKey of the output
    /// @param spendType          0x00 for key-path spend
    /// @param inputIndex         which input is being signed (always 0 here)
    function taprootSighash(
        uint32 version,
        uint32 locktime,
        bytes32 prevoutTxid,
        uint32 prevoutVout,
        uint64 prevoutAmount,
        bytes memory prevoutScriptPubkey,
        uint32 sequence,
        uint64 outputAmount,
        bytes memory outputScriptPubkey,
        uint8 spendType,
        uint32 inputIndex
    ) internal pure returns (bytes32) {
        // sha_prevouts = SHA256(outpoint0) where outpoint = txid (32 LE) || vout (4 LE)
        bytes32 shaPrevouts = sha256(abi.encodePacked(prevoutTxid, u32Le(prevoutVout)));

        // sha_amounts = SHA256(amount0 as u64 LE)
        bytes32 shaAmounts = sha256(u64Le(prevoutAmount));

        // sha_scriptpubkeys = SHA256(compact_size(len) || scriptpubkey)
        require(prevoutScriptPubkey.length < 0xfd, "prev spk too long");
        bytes32 shaScriptpubkeys = sha256(
            abi.encodePacked(uint8(prevoutScriptPubkey.length), prevoutScriptPubkey)
        );

        // sha_sequences = SHA256(sequence0 as u32 LE)
        bytes32 shaSequences = sha256(u32Le(sequence));

        // sha_outputs = SHA256(output0) = amount (8 LE) || compact_size(spk.len) || spk
        require(outputScriptPubkey.length < 0xfd, "out spk too long");
        bytes32 shaOutputs = sha256(
            abi.encodePacked(
                u64Le(outputAmount),
                uint8(outputScriptPubkey.length),
                outputScriptPubkey
            )
        );

        bytes memory preimage = abi.encodePacked(
            uint8(0x00),             // epoch
            uint8(0x00),             // hash_type (SIGHASH_DEFAULT)
            u32Le(version),
            u32Le(locktime),
            shaPrevouts,
            shaAmounts,
            shaScriptpubkeys,
            shaSequences,
            shaOutputs,
            spendType,
            u32Le(inputIndex)
        );

        return taggedHash("TapSighash", preimage);
    }
}
