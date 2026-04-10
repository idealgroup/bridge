// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MintingContract} from "../src/MintingContract.sol";
import {BIP340} from "../src/BIP340.sol";

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

    /// Exercise BIP340.verify against known-good BIP340 test vectors from the
    /// reference CSV (https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).
    function testBIP340Vectors() public view {
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

        // Zeroed signature should fail.
        assertFalse(BIP340.verify(
            bytes32(0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        ));
    }
}
