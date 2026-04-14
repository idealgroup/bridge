// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BIP340 Schnorr signature verification for secp256k1.
/// @notice Implements BIP340 verification using the `ecrecover` precompile trick.
///
/// Reference: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
///
/// The core BIP340 check is: R = s·G - e·P where R has x-coordinate rx and
/// even y. We verify this via the `ecrecover` precompile, which given
/// (msgHash, v, r, s) returns the Ethereum address of
///   Q = r⁻¹ · (s · R' - msgHash · G)
/// where R' is the point with x-coordinate r and y-parity determined by v.
///
/// Setting R' = P (even y), r = px, then
///   Q = px⁻¹ · (sigS·P - msgHash·G)
/// To force Q = s_bip·G - e·P we pick
///   sigS     = (N - e)       · px mod N
///   msgHash  = (N - s_bip)   · px mod N
/// which gives Q = −e·P + s_bip·G = s_bip·G − e·P as required.
///
/// The returned Ethereum address is then compared against the address derived
/// from the BIP340 R point (rx, even_y).
library BIP340 {
    /// @notice secp256k1 field prime p.
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    /// @notice secp256k1 group order n.
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Verify a BIP340 Schnorr signature.
    /// @param px  x-only public key (must be lift-able, i.e. < p and x^3+7 is a QR)
    /// @param rx  signature R.x component (< p)
    /// @param s   signature s component (< n)
    /// @param m   message (typically a 32-byte BIP341 sighash)
    /// @return    true iff the signature is valid
    function verify(bytes32 px, bytes32 rx, bytes32 s, bytes32 m) internal view returns (bool) {
        uint256 pxU = uint256(px);
        uint256 rxU = uint256(rx);
        uint256 sU  = uint256(s);

        // BIP340 requires rx < p and s < n.
        if (rxU >= P) return false;
        if (sU  >= N) return false;

        // px must be a valid x-only pubkey (lift_x must succeed).
        if (pxU == 0 || pxU >= P) return false;
        (bool pxOk, ) = liftX(pxU);
        if (!pxOk) return false;

        // e = int(tagged_hash("BIP0340/challenge", rx || px || m)) mod n
        uint256 e = uint256(taggedHash("BIP0340/challenge", abi.encodePacked(rx, px, m))) % N;

        // ecrecover(msgHash, v, r, s) returns the Ethereum address of
        //   Q = r⁻¹ · (s·R' − msgHash·G)
        // With r = px and v = 27 (P lifted with even y per BIP340), R' = P.
        //
        // Pick:
        //   msgHash = (N − s_bip) · px mod N   (≡ −s·px mod n)
        //   s_sig   = (N − e)     · px mod N   (≡ −e·px mod n)
        //
        // Then Q = px⁻¹ · (−e·px·P − (−s·px)·G) = s·G − e·P, i.e. the BIP340 R.
        uint256 msgHashU = mulmod(N - sU, pxU, N);
        uint256 sigSU    = mulmod(N - e,  pxU, N);

        // ecrecover treats r==0 as invalid; BIP340 rejects px==0 above already.
        address recovered = ecrecover(
            bytes32(msgHashU),
            27,
            bytes32(pxU),
            bytes32(sigSU)
        );
        if (recovered == address(0)) return false;

        // Expected address: Ethereum address of (rx, even_y) — the BIP340 R.
        (bool rxOk, uint256 ry) = liftX(rxU);
        if (!rxOk) return false;
        address expected = pubkeyToAddress(rxU, ry);

        return recovered == expected;
    }

    /// @notice Lift an x-coordinate to the even-y point on secp256k1.
    /// @return (success, y) where y is even; success=false if x has no valid y.
    function liftX(uint256 x) internal view returns (bool, uint256) {
        if (x == 0 || x >= P) return (false, 0);
        uint256 c = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        // y = c^((p+1)/4) mod p
        uint256 y = modExp(c, (P + 1) / 4, P);
        if (mulmod(y, y, P) != c) return (false, 0);
        // Pick even y
        if (y & 1 == 1) {
            y = P - y;
        }
        return (true, y);
    }

    /// @notice Compute Ethereum address of a secp256k1 point (x, y).
    function pubkeyToAddress(uint256 x, uint256 y) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    /// @notice Modular exponentiation via the 0x05 precompile.
    function modExp(uint256 base, uint256 e, uint256 mod_) internal view returns (uint256 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)            // base length
            mstore(add(ptr, 0x20), 0x20) // exp length
            mstore(add(ptr, 0x40), 0x20) // mod length
            mstore(add(ptr, 0x60), base)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), mod_)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }

    /// @notice Verify a BIP340 signature against a taproot-tweaked key, given
    ///         the untweaked internal key and a pre-adjusted signature scalar.
    ///
    /// The caller pre-computes `adjustedS` off-chain:
    ///   - Even y (tweakedKeyOddY=false): adjustedS = s − e·t mod n
    ///   - Odd  y (tweakedKeyOddY=true):  adjustedS = s + e·t mod n
    /// where t = H("TapTweak", P.x || merkleRoot),
    ///       e = H("BIP0340/challenge", rx || tweakedPx || m).
    ///
    /// Security: forging requires breaking standard BIP340 Schnorr
    /// unforgeability against the committee's internal key.
    ///
    /// @param internalPx       committee's untweaked x-only pubkey
    /// @param tweakedPx        claimed tweaked x-only pubkey (used in BIP340 challenge)
    /// @param rx               signature R.x
    /// @param adjustedS        pre-adjusted s' scalar
    /// @param m                message (BIP341 sighash)
    /// @param tweakedKeyOddY   true if the tweaked point Q has odd y
    function verifyTweaked(
        bytes32 internalPx,
        bytes32 tweakedPx,
        bytes32 rx,
        bytes32 adjustedS,
        bytes32 m,
        bool tweakedKeyOddY
    ) internal view returns (bool) {
        uint256 ipxU = uint256(internalPx);
        uint256 rxU  = uint256(rx);
        uint256 asU  = uint256(adjustedS);

        if (rxU >= P || asU >= N) return false;
        if (ipxU == 0 || ipxU >= P) return false;
        (bool ipxOk, ) = liftX(ipxU);
        if (!ipxOk) return false;

        // e = H("BIP0340/challenge", rx || tweakedPx || m) mod n
        uint256 e = uint256(taggedHash("BIP0340/challenge", abi.encodePacked(rx, tweakedPx, m))) % N;

        // Expected R point address
        (bool rxOk, uint256 ry) = liftX(rxU);
        if (!rxOk) return false;
        address expectedR = pubkeyToAddress(rxU, ry);

        // msgHash = (N - adjustedS) · ipx mod N  (same for both parities)
        uint256 msgHash = mulmod(N - asU, ipxU, N);

        // sigS differs by parity of the tweaked key:
        //   Even y: verify s'·G = R + e·P  →  sigS = (N−e)·ipx
        //   Odd  y: verify s'·G + e·P = R  →  sigS = e·ipx
        uint256 sigS = tweakedKeyOddY
            ? mulmod(e, ipxU, N)
            : mulmod(N - e, ipxU, N);

        address recovered = ecrecover(
            bytes32(msgHash),
            27,
            bytes32(ipxU),
            bytes32(sigS)
        );

        return recovered != address(0) && recovered == expectedR;
    }

    /// @notice Tagged hash per BIP340: sha256(sha256(tag) || sha256(tag) || msg)
    function taggedHash(string memory tag, bytes memory data) internal pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, data));
    }
}
