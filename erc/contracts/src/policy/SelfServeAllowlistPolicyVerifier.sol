// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPolicyVerifier} from "../interfaces/IPolicyVerifier.sol";
import {ErcConstants} from "../generated/ErcConstants.sol";
import {Poseidon2Sponge} from "../libraries/Poseidon2Sponge.sol";
import {PoseidonFieldLib} from "../libraries/PoseidonFieldLib.sol";

/// @notice Demo pool-level allowlist policy. Users opt in on-chain, then a gated
///         pool accepts deposit/transact policy data whose public operation
///         details hash back to the pool-supplied policy operation digest.
///
/// @dev Wire format:
///        policyData = abi.encode(uint8 kind, bytes details)
///
///      kind 0 details:
///        abi.encode(
///          address sender,
///          address token,
///          uint256 amount,
///          uint256 ownerCommitment,
///          uint256 outputNoteDataHash
///        )
///
///      kind 1 details:
///        abi.encode(TransactDetails)
///
///      chainId, pool address, and policy verifier address are implicit:
///        block.chainid, msg.sender, address(this).
contract SelfServeAllowlistPolicyVerifier is IPolicyVerifier {
    mapping(address => bool) private allowed;

    event AllowlistJoined(address indexed account);

    struct TransactDetails {
        address authVerifier;
        address authorizingAddress;
        uint256 operationKind;
        address token;
        uint256 recipientOwnerNullifierKeyHash;
        uint256 amount;
        uint256 feeNoteRecipientOwnerNullifierKeyHash;
        uint256 feeAmount;
        address publicRecipientAddress;
        address authorizedSubmitter;
        uint256 downstreamActionCommitment;
        uint256 executionConstraintsFlags;
        uint256 lockedOutputBinding0;
        uint256 lockedOutputBinding1;
        uint256 lockedOutputBinding2;
        uint256 nonce;
        uint256 validUntilSeconds;
        uint256 noteCommitmentRoot;
        uint256 nullifier0;
        uint256 nullifier1;
        uint256 noteBodyCommitment0;
        uint256 noteBodyCommitment1;
        uint256 noteBodyCommitment2;
        uint256 publicAmountOut;
        address publicTokenAddress;
        uint256 intentReplayId;
        uint256 identityRoot;
        uint256 outputNoteDataHash0;
        uint256 outputNoteDataHash1;
        uint256 outputNoteDataHash2;
        uint256 blindedAuthCommitment;
    }

    function joinAllowlist() external {
        allowed[msg.sender] = true;
        emit AllowlistJoined(msg.sender);
    }

    function isAllowed(address account) external view returns (bool) {
        return allowed[account];
    }

    /// @inheritdoc IPolicyVerifier
    function verifyPolicy(bytes calldata publicInputs, bytes calldata policyData)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 32) return false;
        uint256 policyOperationDigest = abi.decode(publicInputs, (uint256));

        (bool ok, uint8 kind, bytes calldata details) = _splitPolicyData(policyData);
        if (!ok) return false;

        if (kind == ErcConstants.POLICY_OPERATION_DEPOSIT) {
            return _verifyDeposit(policyOperationDigest, details);
        }
        if (kind == ErcConstants.POLICY_OPERATION_TRANSACT) {
            return _verifyTransact(policyOperationDigest, details);
        }
        return false;
    }

    function _verifyDeposit(uint256 policyOperationDigest, bytes calldata details)
        private
        view
        returns (bool)
    {
        if (details.length != 160) return false;

        (bool okSender, address sender) = _readAddress(details, 0);
        (bool okToken, address token) = _readAddress(details, 32);
        if (!okSender || !okToken || !allowed[sender]) return false;

        uint256 amount = _word(details, 64);
        uint256 ownerCommitment = _word(details, 96);
        uint256 outputNoteDataHash = _word(details, 128);
        if (!_isField(ownerCommitment) || !_isField(outputNoteDataHash)) return false;

        uint256 opData = PoseidonFieldLib.depositOperationDataHash(
            block.chainid,
            uint256(uint160(msg.sender)),
            uint256(uint160(sender)),
            uint256(uint160(token)),
            amount,
            ownerCommitment,
            outputNoteDataHash
        );
        return policyOperationDigest == _policyOperationDigest(ErcConstants.POLICY_OPERATION_DEPOSIT, opData);
    }

    function _verifyTransact(uint256 policyOperationDigest, bytes calldata details)
        private
        view
        returns (bool)
    {
        (bool ok, TransactDetails memory d) = _decodeTransactDetails(details);
        if (!ok || !allowed[d.authorizingAddress]) return false;

        uint256 fieldsHash = _transactIntentFieldsHash(d);
        uint256 transitionHash = _transactPublicTransitionHash(d);
        uint256 opData = PoseidonFieldLib.transactOperationDataHash(fieldsHash, transitionHash);

        return policyOperationDigest == _policyOperationDigest(ErcConstants.POLICY_OPERATION_TRANSACT, opData);
    }

    function _policyOperationDigest(uint256 kind, uint256 opData) private view returns (uint256) {
        return PoseidonFieldLib.policyOperationDigest(
            block.chainid,
            uint256(uint160(msg.sender)),
            uint256(uint160(address(this))),
            kind,
            opData
        );
    }

    function _decodeTransactDetails(bytes calldata details)
        private
        pure
        returns (bool ok, TransactDetails memory d)
    {
        if (details.length != 992) return (false, d);

        (ok, d.authVerifier) = _readAddress(details, 0);
        if (!ok) return (false, d);
        (ok, d.authorizingAddress) = _readAddress(details, 32);
        if (!ok) return (false, d);
        d.operationKind = _word(details, 64);
        (ok, d.token) = _readAddress(details, 96);
        if (!ok) return (false, d);
        d.recipientOwnerNullifierKeyHash = _word(details, 128);
        d.amount = _word(details, 160);
        d.feeNoteRecipientOwnerNullifierKeyHash = _word(details, 192);
        d.feeAmount = _word(details, 224);
        (ok, d.publicRecipientAddress) = _readAddress(details, 256);
        if (!ok) return (false, d);
        (ok, d.authorizedSubmitter) = _readAddress(details, 288);
        if (!ok) return (false, d);
        d.downstreamActionCommitment = _word(details, 320);
        d.executionConstraintsFlags = _word(details, 352);
        d.lockedOutputBinding0 = _word(details, 384);
        d.lockedOutputBinding1 = _word(details, 416);
        d.lockedOutputBinding2 = _word(details, 448);
        d.nonce = _word(details, 480);
        d.validUntilSeconds = _word(details, 512);
        d.noteCommitmentRoot = _word(details, 544);
        d.nullifier0 = _word(details, 576);
        d.nullifier1 = _word(details, 608);
        d.noteBodyCommitment0 = _word(details, 640);
        d.noteBodyCommitment1 = _word(details, 672);
        d.noteBodyCommitment2 = _word(details, 704);
        d.publicAmountOut = _word(details, 736);
        (ok, d.publicTokenAddress) = _readAddress(details, 768);
        if (!ok) return (false, d);
        d.intentReplayId = _word(details, 800);
        d.identityRoot = _word(details, 832);
        d.outputNoteDataHash0 = _word(details, 864);
        d.outputNoteDataHash1 = _word(details, 896);
        d.outputNoteDataHash2 = _word(details, 928);
        d.blindedAuthCommitment = _word(details, 960);

        return (_transactFieldsCanonical(d), d);
    }

    function _transactFieldsCanonical(TransactDetails memory d) private pure returns (bool) {
        return _isField(d.operationKind)
            && _isField(d.recipientOwnerNullifierKeyHash)
            && _isField(d.amount)
            && _isField(d.feeNoteRecipientOwnerNullifierKeyHash)
            && _isField(d.feeAmount)
            && _isField(d.downstreamActionCommitment)
            && _isField(d.executionConstraintsFlags)
            && _isField(d.lockedOutputBinding0)
            && _isField(d.lockedOutputBinding1)
            && _isField(d.lockedOutputBinding2)
            && _isField(d.nonce)
            && _isField(d.validUntilSeconds)
            && _isField(d.noteCommitmentRoot)
            && _isField(d.nullifier0)
            && _isField(d.nullifier1)
            && _isField(d.noteBodyCommitment0)
            && _isField(d.noteBodyCommitment1)
            && _isField(d.noteBodyCommitment2)
            && _isField(d.publicAmountOut)
            && _isField(d.intentReplayId)
            && _isField(d.identityRoot)
            && _isField(d.outputNoteDataHash0)
            && _isField(d.outputNoteDataHash1)
            && _isField(d.outputNoteDataHash2)
            && _isField(d.blindedAuthCommitment);
    }

    function _transactIntentFieldsHash(TransactDetails memory d) private view returns (uint256) {
        uint256[] memory inputs = new uint256[](20);
        inputs[0] = ErcConstants.TRANSACT_INTENT_FIELDS_DOMAIN;
        inputs[1] = uint256(uint160(msg.sender));
        inputs[2] = uint256(uint160(d.authVerifier));
        inputs[3] = uint256(uint160(d.authorizingAddress));
        inputs[4] = d.operationKind;
        inputs[5] = uint256(uint160(d.token));
        inputs[6] = d.recipientOwnerNullifierKeyHash;
        inputs[7] = d.amount;
        inputs[8] = d.feeNoteRecipientOwnerNullifierKeyHash;
        inputs[9] = d.feeAmount;
        inputs[10] = uint256(uint160(d.publicRecipientAddress));
        inputs[11] = uint256(uint160(d.authorizedSubmitter));
        inputs[12] = d.downstreamActionCommitment;
        inputs[13] = d.executionConstraintsFlags;
        inputs[14] = d.lockedOutputBinding0;
        inputs[15] = d.lockedOutputBinding1;
        inputs[16] = d.lockedOutputBinding2;
        inputs[17] = d.nonce;
        inputs[18] = d.validUntilSeconds;
        inputs[19] = block.chainid;
        return Poseidon2Sponge.hash(inputs);
    }

    function _transactPublicTransitionHash(TransactDetails memory d) private view returns (uint256) {
        uint256[] memory inputs = new uint256[](22);
        inputs[0] = ErcConstants.POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN;
        inputs[1] = d.noteCommitmentRoot;
        inputs[2] = d.nullifier0;
        inputs[3] = d.nullifier1;
        inputs[4] = d.noteBodyCommitment0;
        inputs[5] = d.noteBodyCommitment1;
        inputs[6] = d.noteBodyCommitment2;
        inputs[7] = d.publicAmountOut;
        inputs[8] = uint256(uint160(d.publicRecipientAddress));
        inputs[9] = uint256(uint160(d.publicTokenAddress));
        inputs[10] = d.intentReplayId;
        inputs[11] = d.validUntilSeconds;
        inputs[12] = block.chainid;
        inputs[13] = uint256(uint160(msg.sender));
        inputs[14] = d.identityRoot;
        inputs[15] = d.outputNoteDataHash0;
        inputs[16] = d.outputNoteDataHash1;
        inputs[17] = d.outputNoteDataHash2;
        inputs[18] = uint256(uint160(d.authVerifier));
        inputs[19] = d.blindedAuthCommitment;
        inputs[20] = uint256(uint160(d.authorizedSubmitter));
        inputs[21] = d.downstreamActionCommitment;
        return Poseidon2Sponge.hash(inputs);
    }

    function _splitPolicyData(bytes calldata data)
        private
        pure
        returns (bool ok, uint8 kind, bytes calldata details)
    {
        details = data[:0];
        if (data.length < 96) return (false, 0, details);

        uint256 kindWord = _word(data, 0);
        uint256 offset = _word(data, 32);
        uint256 detailsLen = _word(data, 64);
        if (kindWord > type(uint8).max || offset != 64) return (false, 0, details);
        if (detailsLen > data.length - 96) return (false, 0, details);

        uint256 padded = (detailsLen + 31) & ~uint256(31);
        if (96 + padded != data.length) return (false, 0, details);

        return (true, uint8(kindWord), data[96:96 + detailsLen]);
    }

    function _readAddress(bytes calldata data, uint256 offset)
        private
        pure
        returns (bool ok, address value)
    {
        uint256 raw = _word(data, offset);
        if (raw > type(uint160).max) return (false, address(0));
        return (true, address(uint160(raw)));
    }

    function _word(bytes calldata data, uint256 offset) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := calldataload(add(data.offset, offset))
        }
    }

    function _isField(uint256 value) private pure returns (bool) {
        return value < PoseidonFieldLib.FIELD_MODULUS;
    }
}
