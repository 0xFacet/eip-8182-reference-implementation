// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Shared struct namespace so the pool, the canonical verifier, and
///         libraries reference one PublicInputs layout (spec section 4 —
///         24 fields, declaration order is normative).
interface IShieldedPoolStructs {
    struct PublicInputs {
        uint256 noteCommitmentRoot;
        uint256 nullifier0;
        uint256 nullifier1;
        uint256 noteBodyCommitment0;
        uint256 noteBodyCommitment1;
        uint256 noteBodyCommitment2;
        uint256 publicAmountOut;
        uint256 publicRecipientAddress;
        uint256 publicTokenAddress;
        uint256 intentReplayId;
        uint256 validUntilSeconds;
        uint256 executionChainId;
        uint256 poolAddress;
        uint256 identityRoot;
        uint256 outputNoteDataHash0;
        uint256 outputNoteDataHash1;
        uint256 outputNoteDataHash2;
        uint256 authVerifier;
        uint256 blindedAuthCommitment;
        uint256 transactionIntentDigest;
        uint256 policyOperationDataHash;
        uint256 policyDataHash;
        uint256 authorizedSubmitter;
        uint256 downstreamActionCommitment;
    }
}

/// @notice Conforming pool interface (spec section 4).
interface IShieldedPool is IShieldedPoolStructs {
    event ShieldedPoolTransact(
        uint256 indexed nullifier0,
        uint256 indexed nullifier1,
        uint256 indexed intentReplayId,
        address authVerifier,
        uint256 noteCommitment0,
        uint256 noteCommitment1,
        uint256 noteCommitment2,
        uint256 leafIndex0,
        uint256 postInsertionCommitmentRoot,
        bytes outputNoteData0,
        bytes outputNoteData1,
        bytes outputNoteData2
    );

    event ShieldedPoolDeposit(
        address indexed depositor,
        uint256 noteCommitment,
        uint256 leafIndex,
        uint256 amount,
        uint256 tokenAddress,
        uint256 postInsertionCommitmentRoot,
        bytes outputNoteData
    );

    function transact(
        bytes calldata poolProof,
        bytes calldata authProof,
        PublicInputs calldata publicInputs,
        bytes calldata outputNoteData0,
        bytes calldata outputNoteData1,
        bytes calldata outputNoteData2,
        bytes calldata policyData
    ) external;

    function deposit(
        address token,
        uint256 amount,
        uint256 ownerCommitment,
        bytes calldata outputNoteData,
        bytes calldata policyData
    ) external payable;

    function getCurrentRoots()
        external
        view
        returns (uint256 noteCommitmentRoot, uint256 identityRoot);

    function poseidonParametersDigest() external pure returns (bytes32);
    function outputNoteDataSuite() external pure returns (string memory);
    function policyVerifier() external view returns (address);
    function policyAppliesToOperations() external view returns (uint256);

    function isAcceptedNoteCommitmentRoot(uint256 root) external view returns (bool);
    function isNullifierSpent(uint256 nullifier) external view returns (bool);
    function isIntentReplayIdUsed(uint256 intentReplayId) external view returns (bool);
}
