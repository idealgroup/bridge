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

    /// Exercise BIP340.verify against the reference BIP340 test vectors from
    /// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv.
    /// Covers a mix of positive vectors and the edge-case negative vectors
    /// that exercise the explicit range/validity checks in `BIP340.verify`.
    function testBIP340Vectors() public view {
        // --- Positive vectors ---

        // Vector index 0
        assertTrue(BIP340.verify(
            bytes32(0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9),
            bytes32(0xE907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215),
            bytes32(0x25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0),
            bytes32(0x0000000000000000000000000000000000000000000000000000000000000000)
        ));

        // Vector index 1
        assertTrue(BIP340.verify(
            bytes32(0xDFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659),
            bytes32(0x6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341),
            bytes32(0x8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A),
            bytes32(0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89)
        ));

        // Vector index 2
        assertTrue(BIP340.verify(
            bytes32(0xDD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8),
            bytes32(0x5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B),
            bytes32(0xAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7),
            bytes32(0x7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C)
        ));

        // --- Negative vectors from the reference CSV ---
        // These use a common valid pubkey & message, varying the (rx, s) pair
        // to hit each rejection branch.
        bytes32 px  = 0xDFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659;
        bytes32 msg_ = 0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89;

        // Vector index 5: public key not on the curve. (Different px.)
        assertFalse(BIP340.verify(
            bytes32(0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34),
            bytes32(0x6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769),
            bytes32(0x69961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6D),
            msg_
        ));

        // Vector index 7: negated message (sig is valid but for -m).
        assertFalse(BIP340.verify(
            px,
            bytes32(0x1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F),
            bytes32(0x28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD),
            msg_
        ));

        // Vector index 8: negated s value.
        assertFalse(BIP340.verify(
            px,
            bytes32(0x6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769),
            bytes32(0xFD0B48C3C7F0CE65A6A47C9D90C7EDBC0D8E80E7D0C6FD3D3DC4EEBEFBB1DD44),
            msg_
        ));

        // Vector index 11: sig[0:32] (rx) equals the field size p — must fail
        // the `rxU >= P` guard.
        assertFalse(BIP340.verify(
            px,
            bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F),
            bytes32(0x7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197),
            msg_
        ));

        // Vector index 12: sig[32:64] (s) equals the curve order n — must fail
        // the `sU >= N` guard.
        assertFalse(BIP340.verify(
            px,
            bytes32(0x6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769),
            bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
            msg_
        ));

        // Vector index 13: public key > field size — must fail the
        // `pxU >= P` guard (or liftX, whichever catches it first).
        assertFalse(BIP340.verify(
            bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30),
            bytes32(0x6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769),
            bytes32(0x3B5D5165383C2AAE0867F69AD90DC48FEFEBAE01F00C722AA2EAC13776A27370),
            msg_
        ));

        // Trivially zeroed signature should also fail.
        assertFalse(BIP340.verify(
            bytes32(0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        ));
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
