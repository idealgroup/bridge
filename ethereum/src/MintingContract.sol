// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {BIP340} from "./BIP340.sol";
import {BIP341} from "./BIP341.sol";
import {TxParser} from "./TxParser.sol";

/// @title MintingContract — Ethereum side of the ideal-bridge.
/// @notice Manages wBTC minting/burning backed by Bitcoin deposits. Verifies
///         the committee's BIP340 Schnorr signature on the deterministic
///         depositTx to confirm deposits, and reconstructs the BIP341 sighash
///         directly on-chain from the parsed requestTx bytes.
contract MintingContract is ERC20 {
    // Dust threshold (sats) — mirrors DUST_AMOUNT on the Bitcoin side.
    uint64 public constant DUST_AMOUNT = 546;

    // Taproot tx constants used to reconstruct the depositTx sighash.
    uint32 internal constant TX_VERSION = 2;
    uint32 internal constant LOCKTIME = 0;
    uint32 internal constant SEQUENCE_RBF = 0xFFFFFFFD;

    /// @notice Deposit output scriptPubKey: `0x51 0x20 || tweaked_committee_x`
    ///         where `tweaked_committee_x` = x-only of P + int(tagged_hash("TapTweak", P))·G
    ///         (BIP341 tap tweak, no script tree). Pre-computed off-chain at
    ///         deployment time to avoid expensive on-chain scalar multiplication.
    bytes public depositScriptPubkey;

    /// @notice Mint delay, in seconds.
    uint64 public immutable mintDelay;

    enum DepositStatus {
        None,
        Pending,
        Minted,
        Cancelled
    }

    struct DepositInfo {
        address recipient;
        bytes32 depositSecretHash;
        uint64 requestTimestamp;
        DepositStatus status;
        uint64 amount; // satoshis
    }

    mapping(bytes32 => DepositInfo) public deposits;

    event Request(bytes32 indexed depositSecretHash, address indexed recipient, uint64 timestamp);
    event Mint(bytes32 indexed depositSecretHash, address indexed recipient, uint64 amount);
    event Cancel(bytes32 indexed depositSecretHash, address cancelledBy);
    event Burn(address indexed account, uint256 amount);

    /// @param _depositTweakedPubkey x-only P2TR output key for the committee's
    ///        depositTx output (BIP341 tap-tweaked committee pubkey, no script
    ///        tree). Computed off-chain by the deployer.
    /// @param _mintDelay Number of seconds between `request` and `mint`.
    constructor(bytes32 _depositTweakedPubkey, uint64 _mintDelay) ERC20("Wrapped BTC", "wBTC") {
        depositScriptPubkey = abi.encodePacked(bytes1(0x51), bytes1(0x20), _depositTweakedPubkey);
        mintDelay = _mintDelay;
    }

    /// @notice wBTC uses 8 decimals to mirror Bitcoin's satoshi precision.
    function decimals() public pure override returns (uint8) {
        return 8;
    }

    /// @notice Submit a deposit request with the committee's signature on the depositTx.
    ///
    /// Anyone can call this. The recipient is extracted from the requestTx's OP_RETURN.
    function request(
        bytes calldata rawRequestTx,
        bytes32 depositSecretHash,
        bytes32 sigRx,
        bytes32 sigS
    ) external {
        // Parse the requestTx
        TxParser.RequestTxData memory tx_ = TxParser.parseRequestTx(rawRequestTx);

        // Check this deposit hasn't been requested before
        require(deposits[depositSecretHash].status == DepositStatus.None, "deposit already requested");

        // Derive deposit output amount from request output (ground truth):
        // deposit_output_amount = request_output0_amount - DUST_AMOUNT
        require(tx_.output0Amount > DUST_AMOUNT, "request output too small");
        uint64 depositOutputAmount = tx_.output0Amount - DUST_AMOUNT;

        // The request output is P2TR: 0x51 0x20 || <tweaked_pubkey>. The
        // committee signed with the key tweaked by the request output's
        // taproot tree, so we verify against the tweaked pubkey extracted
        // directly from the output's scriptPubKey.
        bytes memory spk = tx_.output0ScriptPubkey;
        require(spk.length == 34, "bad P2TR script length");
        require(uint8(spk[0]) == 0x51 && uint8(spk[1]) == 0x20, "bad P2TR prefix");
        bytes32 tweakedPk;
        assembly {
            // spk layout in memory: [32-byte length][data...]. Skip the 2-byte
            // 0x5120 prefix -> offset = data_ptr + 2 = spk_ptr + 32 + 2.
            tweakedPk := mload(add(spk, 34))
        }

        // Reconstruct the depositTx BIP341 sighash
        bytes32 sighash = BIP341.taprootSighash(
            TX_VERSION,
            LOCKTIME,
            tx_.txid,
            0, // prevout vout (always output 0 of requestTx)
            tx_.output0Amount,
            spk,
            SEQUENCE_RBF,
            depositOutputAmount,
            depositScriptPubkey,
            0x00, // spend_type: key-path
            0     // input_index
        );

        // Verify the committee's BIP340 signature against the tweaked pubkey
        require(BIP340.verify(tweakedPk, sigRx, sigS, sighash), "invalid committee signature");

        // Store deposit info. `amount` is the value actually locked in the
        // committee's depositTx output (request output minus DUST_AMOUNT),
        // not the requestTx output itself — that's what backs the minted wBTC.
        deposits[depositSecretHash] = DepositInfo({
            recipient: tx_.recipient,
            depositSecretHash: depositSecretHash,
            requestTimestamp: uint64(block.timestamp),
            status: DepositStatus.Pending,
            amount: depositOutputAmount
        });

        emit Request(depositSecretHash, tx_.recipient, uint64(block.timestamp));
    }

    /// @notice Mint wBTC after the delay period has elapsed.
    function mint(bytes32 depositSecretHash) external {
        DepositInfo memory d = deposits[depositSecretHash];
        require(d.status == DepositStatus.Pending, "not pending");
        require(block.timestamp >= d.requestTimestamp + mintDelay, "mint delay not elapsed");

        deposits[depositSecretHash].status = DepositStatus.Minted;

        _mint(d.recipient, uint256(d.amount));

        emit Mint(depositSecretHash, d.recipient, d.amount);
    }

    /// @notice Cancel a pending deposit by revealing the deposit secret preimage.
    function cancel(bytes32 depositSecret) external {
        bytes32 depositSecretHash = sha256(abi.encodePacked(depositSecret));
        DepositInfo memory d = deposits[depositSecretHash];
        require(d.status == DepositStatus.Pending, "not pending");

        deposits[depositSecretHash].status = DepositStatus.Cancelled;

        emit Cancel(depositSecretHash, msg.sender);
    }

    /// @notice Burn wBTC (user initiates withdrawal from Ethereum back to Bitcoin).
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }
}
