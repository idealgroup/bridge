// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MintingContract} from "../src/MintingContract.sol";
import {BIP340} from "../src/BIP340.sol";
import {TxParser} from "../src/TxParser.sol";

/// Thin harness so we can call the internal `TxParser.parseRequestTx` from tests
/// via an external call, which lets `vm.expectRevert` observe the revert.
contract TxParserHarness {
    function parse(bytes calldata raw) external pure {
        TxParser.parseRequestTx(raw);
    }
}

contract MintingContractTest is Test {
    // Dummy tweaked committee pubkey (valid x-only, lifts to a point).
    // This is generator.x, which is a valid curve point.
    bytes32 constant DUMMY_TWEAKED_PK = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint64 constant MINT_DELAY = 86400;

    MintingContract minting;

    function setUp() public {
        minting = new MintingContract(DUMMY_TWEAKED_PK, MINT_DELAY);
    }

    function testDeploy() public view {
        assertEq(minting.name(), "Wrapped BTC");
        assertEq(minting.symbol(), "wBTC");
        assertEq(minting.decimals(), 8);
        assertEq(minting.totalSupply(), 0);
        assertEq(minting.mintDelay(), MINT_DELAY);
    }

    function testCancelWithWrongSecretNoMatch() public {
        // Cancel with a secret whose hash doesn't match any pending deposit.
        vm.expectRevert("not pending");
        minting.cancel(bytes32(uint256(0xdeadbeef)));
    }

    function testMintNonexistentDeposit() public {
        vm.expectRevert("not pending");
        minting.mint(bytes32(uint256(0x1234)));
    }

    function testBurnNoBalance() public {
        // Default caller has zero balance — burn should revert with ERC20 error.
        vm.expectRevert();
        minting.burn(1);
    }

    /// All BIP340 test vectors from the official reference CSV:
    /// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    ///
    /// Vectors 15–18 have non-32-byte messages and are skipped automatically
    /// (our BIP340.verify accepts only bytes32, matching the contract's use case).
    function testBIP340Vectors() public {
        string memory path = "test/fixtures/bip340-test-vectors.csv";
        vm.readLine(path); // skip header

        uint256 tested;
        for (uint256 i = 0; i < 19; i++) {
            string memory line = vm.readLine(path);
            if (bytes(line).length == 0) break;

            // Locate the 7 commas separating the 8 CSV fields.
            bytes memory b = bytes(line);
            uint256[7] memory c;
            uint256 pos;
            for (uint256 j = 0; j < 7; j++) {
                pos = _nextComma(b, pos);
                c[j] = pos;
                pos++;
            }

            // field 4 = message hex (between commas 3 and 4)
            uint256 msgStart = c[3] + 1;
            uint256 msgLen = c[4] - msgStart;
            if (msgLen != 64) continue; // skip non-32-byte messages

            bytes32 pk = _hex32(b, c[1] + 1);
            bytes32 m  = _hex32(b, msgStart);
            bytes32 rx = _hex32(b, c[4] + 1);
            bytes32 s  = _hex32(b, c[4] + 65);
            bool expect = uint8(b[c[5] + 1]) == 0x54; // 'T' = TRUE

            assertEq(BIP340.verify(pk, rx, s, m), expect, string.concat("vector ", vm.toString(i)));
            tested++;
        }
        assertEq(tested, 15, "expected 15 applicable vectors");
    }

    function _nextComma(bytes memory b, uint256 from) private pure returns (uint256) {
        for (uint256 i = from; i < b.length; i++) {
            if (uint8(b[i]) == 0x2C) return i;
        }
        return b.length;
    }

    function _hex32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 i = 0; i < 32; i++) {
            uint8 hi = _hexVal(uint8(b[offset + 2 * i]));
            uint8 lo = _hexVal(uint8(b[offset + 2 * i + 1]));
            result |= bytes32(bytes1(uint8(hi << 4 | lo))) >> (i * 8);
        }
    }

    function _hexVal(uint8 c) private pure returns (uint8) {
        if (c >= 0x30 && c <= 0x39) return c - 0x30; // '0'-'9'
        if (c >= 0x41 && c <= 0x46) return c - 0x37; // 'A'-'F'
        if (c >= 0x61 && c <= 0x66) return c - 0x57; // 'a'-'f'
        revert("bad hex");
    }

    /// TxParser should reject malformed / truncated transactions with a clear
    /// error rather than a panic from out-of-bounds calldata access.
    function testTxParserRejectsTruncated() public {
        TxParserHarness harness = new TxParserHarness();

        // Empty buffer.
        vm.expectRevert("tx too short");
        harness.parse("");

        // Just the version bytes — truncated before input count.
        vm.expectRevert("tx too short");
        harness.parse(hex"02000000");

        // Long enough to pass the upfront min-length check (67 bytes) but
        // with a claimed input script that runs off the end of the buffer.
        // Layout: version(4) + in_count(1)=1 + txid(32) + vout(4)
        //       + script_len(1)=0xff...impossible value.
        bytes memory padded = new bytes(70);
        padded[0] = 0x02; // version
        padded[4] = 0x01; // 1 input
        // offset 5..41: outpoint (all zero is fine)
        padded[41] = 0xfc; // script_len = 252, way past buffer end
        vm.expectRevert("truncated tx");
        harness.parse(padded);

        // Too many inputs: in_count = 0xfd 0x41 0x00 = 65 > MAX_INPUTS.
        bytes memory tooMany = new bytes(100);
        tooMany[0] = 0x02;
        tooMany[4] = 0xfd;
        tooMany[5] = 0x41;
        tooMany[6] = 0x00;
        vm.expectRevert("too many inputs");
        harness.parse(tooMany);
    }
}
