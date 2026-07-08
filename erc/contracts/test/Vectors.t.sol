// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";
import {Poseidon2Sponge} from "../src/libraries/Poseidon2Sponge.sol";
import {ErcConstants} from "../src/generated/ErcConstants.sol";
import {IShieldedPoolStructs} from "../src/interfaces/IShieldedPool.sol";

/// @notice Locks the Solidity hash surface to assets/derivation_vectors.json —
///         the same file that gates the Circom, Noir, and TS surfaces.
contract VectorsTest is Test {
    using stdJson for string;

    string internal json;

    function setUp() public {
        json = vm.readFile("../assets/derivation_vectors.json");
    }

    function _u(string memory key) internal view returns (uint256) {
        return json.readUint(key);
    }

    function test_domainTagsMatchGeneratedConstants() public view {
        assertEq(
            _u(".primitives.merkleNode.out"),
            Poseidon2Sponge.hashPair(1, 2),
            "merkle node hash"
        );
        // Recompute two tags from first principles to catch codegen drift.
        assertEq(
            ErcConstants.IDENTITY_LEAF_DOMAIN,
            uint256(keccak256("erc-app-layer-private-transfers.identity_leaf")) % ErcConstants.P,
            "identity leaf tag"
        );
        assertEq(
            ErcConstants.POLICY_OPERATION_DOMAIN,
            uint256(keccak256("erc-app-layer-private-transfers.policy_operation")) % ErcConstants.P,
            "policy operation tag"
        );
    }

    function test_emptyLadder() public view {
        // EMPTY[h+1] = poseidon(EMPTY[h], EMPTY[h]); vectors pin depth 8 + 32.
        uint256 node = 0;
        for (uint256 h = 0; h < 8; h++) node = Poseidon2Sponge.hashPair(node, node);
        assertEq(node, _u(".primitives.emptyRoots.depth8"), "empty root depth 8");
        for (uint256 h = 8; h < 32; h++) node = Poseidon2Sponge.hashPair(node, node);
        assertEq(node, _u(".primitives.emptyRoots.depth32"), "empty root depth 32");
    }

    function test_identityLeaf() public view {
        assertEq(
            PoseidonFieldLib.identityLeaf(
                address(uint160(_u(".identities.sender.address"))),
                _u(".identities.sender.ownerNullifierKeyHash"),
                _u(".identities.sender.noteSecretSeedHash"),
                _u(".identities.sender.policySetCommitment")
            ),
            _u(".identities.sender.identityLeaf"),
            "sender identity leaf"
        );
    }

    function test_dummyOwnerHash() public view {
        assertEq(
            ErcConstants.DUMMY_OWNER_NULLIFIER_KEY_HASH,
            Poseidon2Sponge.hashPair(ErcConstants.OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead),
            "dummy = poseidon(tag, 0xdead)"
        );
        assertEq(
            ErcConstants.DUMMY_OWNER_NULLIFIER_KEY_HASH,
            _u(".dummyOwnerNullifierKeyHash"),
            "dummy matches vectors"
        );
    }

    function test_depositSealing() public view {
        // nbc = poseidon(NBC_DOMAIN, ownerCommitment, amount, token);
        // noteCommitment = poseidon(NC_DOMAIN, chainId, pool, nbc, leafIndex)
        uint256 nbc = PoseidonFieldLib.noteBodyCommitment(
            _u(".deposit.ownerCommitment"),
            12345,
            0
        );
        assertEq(nbc, _u(".deposit.noteBodyCommitment"), "deposit nbc");
        assertEq(
            PoseidonFieldLib.noteCommitment(_u(".chainId"), _u(".poolAddress"), nbc, 7),
            _u(".deposit.noteCommitment"),
            "deposit note commitment"
        );
    }

    function test_depositPolicyDigests() public view {
        uint256 opData = PoseidonFieldLib.depositOperationDataHash(
            _u(".chainId"),
            _u(".poolAddress"),
            _u(".identities.sender.address"),
            0,
            12345,
            _u(".deposit.ownerCommitment"),
            _u(".deposit.outputNoteDataHash")
        );
        assertEq(opData, _u(".deposit.depositOperationDataHash"), "deposit op data hash");
        assertEq(
            PoseidonFieldLib.policyOperationDigest(
                _u(".chainId"),
                _u(".poolAddress"),
                _u(".policyVerifier"),
                ErcConstants.POLICY_OPERATION_DEPOSIT,
                opData
            ),
            _u(".deposit.policyOperationDigestDeposit"),
            "deposit policy digest"
        );
    }

    function _publicInputs(string memory scenario)
        internal
        view
        returns (IShieldedPoolStructs.PublicInputs memory pi)
    {
        uint256[] memory arr = json.readUintArray(string.concat(".scenarios.", scenario, ".publicInputs"));
        require(arr.length == 24, "expected 24 public inputs");
        pi.noteCommitmentRoot = arr[0];
        pi.nullifier0 = arr[1];
        pi.nullifier1 = arr[2];
        pi.noteBodyCommitment0 = arr[3];
        pi.noteBodyCommitment1 = arr[4];
        pi.noteBodyCommitment2 = arr[5];
        pi.publicAmountOut = arr[6];
        pi.publicRecipientAddress = arr[7];
        pi.publicTokenAddress = arr[8];
        pi.intentReplayId = arr[9];
        pi.validUntilSeconds = arr[10];
        pi.executionChainId = arr[11];
        pi.poolAddress = arr[12];
        pi.identityRoot = arr[13];
        pi.outputNoteDataHash0 = arr[14];
        pi.outputNoteDataHash1 = arr[15];
        pi.outputNoteDataHash2 = arr[16];
        pi.authVerifier = arr[17];
        pi.blindedAuthCommitment = arr[18];
        pi.transactionIntentDigest = arr[19];
        pi.policyOperationDataHash = arr[20];
        pi.policyDataHash = arr[21];
        pi.authorizedSubmitter = arr[22];
        pi.downstreamActionCommitment = arr[23];
    }

    function test_transactPolicyDigests_transfer() public {
        this._checkTransition("transfer");
    }

    function test_transactPolicyDigests_withdrawal() public {
        this._checkTransition("withdrawal");
        // policyOperationDigest for the gated withdrawal
        uint256 opData = _u(".scenarios.withdrawal.transactOperationDataHash");
        assertEq(
            PoseidonFieldLib.policyOperationDigest(
                _u(".chainId"),
                _u(".poolAddress"),
                _u(".policyVerifier"),
                ErcConstants.POLICY_OPERATION_TRANSACT,
                opData
            ),
            _u(".scenarios.withdrawal.policyOperationDigest"),
            "withdrawal policy operation digest"
        );
    }

    // external so the struct can be calldata (library takes calldata)
    function _checkTransition(string calldata scenario) external view {
        IShieldedPoolStructs.PublicInputs memory piMem = _publicInputs(scenario);
        uint256 transition = this._transitionHash(piMem);
        assertEq(
            transition,
            _u(string.concat(".scenarios.", scenario, ".transactPublicTransitionHash")),
            "transition hash"
        );
        assertEq(
            PoseidonFieldLib.transactOperationDataHash(
                _u(string.concat(".scenarios.", scenario, ".transactIntentFieldsHash")),
                transition
            ),
            _u(string.concat(".scenarios.", scenario, ".transactOperationDataHash")),
            "operation data hash"
        );
    }

    function _transitionHash(IShieldedPoolStructs.PublicInputs calldata pi)
        external
        pure
        returns (uint256)
    {
        return PoseidonFieldLib.transactPublicTransitionHash(pi);
    }

    function test_keccakFieldEmptyPolicyData() public view {
        assertEq(
            this.keccakFieldExt(hex""),
            _u(".emptyPolicyDataHash"),
            "empty policy data hash"
        );
    }

    function keccakFieldExt(bytes calldata data) external pure returns (uint256) {
        return PoseidonFieldLib.keccakField(data);
    }
}
