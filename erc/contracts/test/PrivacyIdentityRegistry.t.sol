// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PrivacyIdentityRegistry} from "../src/PrivacyIdentityRegistry.sol";
import {IPrivacyIdentityRegistry} from "../src/interfaces/IPrivacyIdentityRegistry.sol";
import {ErcConstants} from "../src/generated/ErcConstants.sol";

contract PrivacyIdentityRegistryTest is Test {
    using stdJson for string;

    PrivacyIdentityRegistry internal registry;
    string internal json;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    uint256 internal constant ONK_A = 111;
    uint256 internal constant SEED_A = 222;
    uint256 internal constant PSET_A = 333;

    function setUp() public {
        registry = new PrivacyIdentityRegistry();
        json = vm.readFile("../assets/derivation_vectors.json");
        vm.roll(1000); // start above the history window
    }

    // ---------------- setIdentity validation ----------------

    function test_rejectsNonCanonicalFieldElements() public {
        uint256 p = ErcConstants.P;
        vm.startPrank(alice);
        vm.expectRevert(PrivacyIdentityRegistry.FieldElementNotCanonical.selector);
        registry.setIdentity(p, SEED_A, PSET_A);
        vm.expectRevert(PrivacyIdentityRegistry.FieldElementNotCanonical.selector);
        registry.setIdentity(ONK_A, p, PSET_A);
        vm.expectRevert(PrivacyIdentityRegistry.FieldElementNotCanonical.selector);
        registry.setIdentity(ONK_A, SEED_A, p);
        vm.stopPrank();
    }

    function test_rejectsReservedOwnerHashes() public {
        vm.startPrank(alice);
        vm.expectRevert(PrivacyIdentityRegistry.ReservedOwnerNullifierKeyHash.selector);
        registry.setIdentity(0, SEED_A, PSET_A);
        vm.expectRevert(PrivacyIdentityRegistry.ReservedOwnerNullifierKeyHash.selector);
        registry.setIdentity(ErcConstants.DUMMY_OWNER_NULLIFIER_KEY_HASH, SEED_A, PSET_A);
        vm.expectRevert(PrivacyIdentityRegistry.ZeroNoteSecretSeedHash.selector);
        registry.setIdentity(ONK_A, 0, PSET_A);
        vm.stopPrank();
    }

    function test_firstRegistrationAssignsSequentialPositions() public {
        vm.prank(alice);
        uint32 posA = registry.setIdentity(ONK_A, SEED_A, PSET_A);
        assertEq(posA, 1, "first position is 1 (slot 0 sentinel)");

        vm.prank(bob);
        uint32 posB = registry.setIdentity(ONK_A + 1, SEED_A, PSET_A);
        assertEq(posB, 2, "second position is 2");

        (bool regA, IPrivacyIdentityRegistry.IdentityEntry memory entryA) = registry.getIdentityEntry(alice);
        assertTrue(regA);
        assertEq(entryA.leafPosition, 1);
        assertEq(entryA.ownerNullifierKeyHash, ONK_A);

        (bool regC,) = registry.getIdentityEntry(address(0xCAFE));
        assertFalse(regC, "unregistered address");
    }

    function test_onkUniquenessAcrossAddresses() public {
        vm.prank(alice);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);
        vm.prank(bob);
        vm.expectRevert(PrivacyIdentityRegistry.OwnerNullifierKeyHashAlreadyUsed.selector);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);
    }

    function test_onkImmutablePerAddress_seedAndPolicySetRotatable() public {
        vm.startPrank(alice);
        uint32 pos1 = registry.setIdentity(ONK_A, SEED_A, PSET_A);
        vm.expectRevert(PrivacyIdentityRegistry.OwnerNullifierKeyHashImmutable.selector);
        registry.setIdentity(ONK_A + 1, SEED_A, PSET_A);

        uint32 pos2 = registry.setIdentity(ONK_A, SEED_A + 1, PSET_A + 1);
        vm.stopPrank();
        assertEq(pos1, pos2, "position stable across updates");

        (, IPrivacyIdentityRegistry.IdentityEntry memory entry) = registry.getIdentityEntry(alice);
        assertEq(entry.noteSecretSeedHash, SEED_A + 1);
        assertEq(entry.policySetCommitment, PSET_A + 1);
    }

    // ---------------- roots ----------------

    function test_emptyRootMatchesVectors() public view {
        assertEq(
            registry.getCurrentIdentityRoot(),
            json.readUint(".primitives.emptyRoots.depth32"),
            "fresh registry root = EMPTY[32]"
        );
    }

    /// @dev The key cross-surface invariant: replaying the vector registrations
    ///      on-chain reproduces the SDK-computed identity root used by the
    ///      circuit vectors.
    function test_vectorIdentityRootReproduced() public {
        address sender = address(uint160(json.readUint(".identities.sender.address")));
        address recipient = address(uint160(json.readUint(".identities.recipient.address")));

        vm.prank(sender);
        uint32 p1 = registry.setIdentity(
            json.readUint(".identities.sender.ownerNullifierKeyHash"),
            json.readUint(".identities.sender.noteSecretSeedHash"),
            json.readUint(".identities.sender.policySetCommitment")
        );
        vm.prank(recipient);
        uint32 p2 = registry.setIdentity(
            json.readUint(".identities.recipient.ownerNullifierKeyHash"),
            json.readUint(".identities.recipient.noteSecretSeedHash"),
            json.readUint(".identities.recipient.policySetCommitment")
        );
        assertEq(p1, 1);
        assertEq(p2, 2);
        assertEq(
            registry.getCurrentIdentityRoot(),
            json.readUint(".identities.identityRoot"),
            "on-chain root == SDK/vector identity root"
        );
        assertTrue(registry.isAcceptedIdentityRoot(json.readUint(".identities.identityRoot")));
    }

    function test_rootZeroNeverAccepted() public view {
        assertFalse(registry.isAcceptedIdentityRoot(0));
    }

    function test_rootHistoryWindowAcceptsThenExpires() public {
        uint256 rootBefore = registry.getCurrentIdentityRoot();

        vm.prank(alice);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);
        assertTrue(registry.isAcceptedIdentityRoot(rootBefore), "pre-mutation root still accepted");

        // Within the window (64 blocks) the old root stays accepted.
        vm.roll(block.number + 64);
        assertTrue(registry.isAcceptedIdentityRoot(rootBefore), "accepted at exactly W blocks");

        // Past the window it expires.
        vm.roll(block.number + 1);
        assertFalse(registry.isAcceptedIdentityRoot(rootBefore), "rejected past W blocks");

        // Current root always accepted.
        assertTrue(registry.isAcceptedIdentityRoot(registry.getCurrentIdentityRoot()));
    }

    function test_sameBlockMutationsKeepOnlyStartOfBlockRoot() public {
        uint256 startRoot = registry.getCurrentIdentityRoot();

        vm.prank(alice);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);
        uint256 intermediateRoot = registry.getCurrentIdentityRoot();

        // Same block: second mutation must NOT snapshot intermediateRoot.
        vm.prank(bob);
        registry.setIdentity(ONK_A + 1, SEED_A, PSET_A);

        vm.roll(block.number + 1);
        assertTrue(registry.isAcceptedIdentityRoot(startRoot), "start-of-block root retained");
        assertFalse(
            registry.isAcceptedIdentityRoot(intermediateRoot),
            "intermediate same-block root not retained"
        );
    }

    function test_ringBufferHoldsWindowUnderChurn() public {
        uint256 rootBefore = registry.getCurrentIdentityRoot();
        vm.prank(alice);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);

        // Churn one mutation per block for 64 blocks; rootBefore must survive
        // exactly through the window even under maximum snapshot churn.
        for (uint256 i = 1; i <= 64; i++) {
            vm.roll(block.number + 1);
            vm.prank(alice);
            registry.setIdentity(ONK_A, SEED_A, PSET_A + i);
            if (i < 64) {
                assertTrue(registry.isAcceptedIdentityRoot(rootBefore), "accepted during window");
            }
        }
        // rootBefore was snapshotted at block B; we're now at B+64 — still in window.
        assertTrue(registry.isAcceptedIdentityRoot(rootBefore), "at window edge");
        vm.roll(block.number + 1);
        vm.prank(alice);
        registry.setIdentity(ONK_A, SEED_A, PSET_A + 999);
        assertFalse(registry.isAcceptedIdentityRoot(rootBefore), "expired after window");
    }

    // ---------------- receive plane ----------------

    function _kemKey() internal pure returns (bytes memory key) {
        key = new bytes(1184);
        key[0] = 0x42;
    }

    function test_receiveProfileLengthCheck() public {
        vm.startPrank(alice);
        vm.expectRevert(PrivacyIdentityRegistry.InvalidMlKemPublicKeyLength.selector);
        registry.setReceiveProfile(new bytes(1183), 1);
        vm.expectRevert(PrivacyIdentityRegistry.InvalidMlKemPublicKeyLength.selector);
        registry.setReceiveProfile(new bytes(1185), 1);
        registry.setReceiveProfile(_kemKey(), 7);
        vm.stopPrank();

        (bool reg, IPrivacyIdentityRegistry.ReceiveEntry memory entry) = registry.getReceiveEntry(alice);
        assertTrue(reg);
        assertEq(entry.metadataVersion, 7);
        assertEq(entry.mlKem768PublicKey.length, 1184);
        assertEq(entry.mlKem768PublicKey[0], bytes1(0x42));
    }

    function test_receiveUpdatesDoNotTouchIdentityRoot() public {
        vm.prank(alice);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);
        uint256 root = registry.getCurrentIdentityRoot();

        vm.prank(alice);
        registry.setReceiveProfile(_kemKey(), 1);
        assertEq(registry.getCurrentIdentityRoot(), root, "receive plane never moves the identity root");
    }

    function test_clearReceiveProfile() public {
        vm.startPrank(alice);
        registry.setReceiveProfile(_kemKey(), 1);
        vm.expectEmit(true, false, false, true);
        emit IPrivacyIdentityRegistry.ReceiveProfileCleared(alice, 2);
        registry.clearReceiveProfile(2);
        vm.stopPrank();

        (bool reg,) = registry.getReceiveEntry(alice);
        assertFalse(reg, "cleared");
    }

    function test_setFullProfileAtomic() public {
        vm.prank(alice);
        uint32 pos = registry.setFullProfile(ONK_A, SEED_A, PSET_A, _kemKey(), 3);
        assertEq(pos, 1);

        (
            bool identityRegistered,
            IPrivacyIdentityRegistry.IdentityEntry memory identity,
            bool receiveRegistered,
            IPrivacyIdentityRegistry.ReceiveEntry memory receiveEntry
        ) = registry.getPrivacyProfile(alice);
        assertTrue(identityRegistered);
        assertTrue(receiveRegistered);
        assertEq(identity.ownerNullifierKeyHash, ONK_A);
        assertEq(receiveEntry.metadataVersion, 3);
    }

    function test_setFullProfileRevertsAtomically() public {
        // bad kem key length must revert the identity write too
        vm.prank(alice);
        vm.expectRevert(PrivacyIdentityRegistry.InvalidMlKemPublicKeyLength.selector);
        registry.setFullProfile(ONK_A, SEED_A, PSET_A, new bytes(10), 3);

        (bool reg,) = registry.getIdentityEntry(alice);
        assertFalse(reg, "identity write rolled back");
    }

    // ---------------- events & introspection ----------------

    function test_identitySetEventFields() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, false);
        emit IPrivacyIdentityRegistry.IdentitySet(alice, ONK_A, SEED_A, PSET_A, 1, 0, 0);
        registry.setIdentity(ONK_A, SEED_A, PSET_A);
    }

    function test_introspection() public view {
        assertEq(
            registry.ercXXXXPrivacyRegistryId(),
            keccak256("ERCXXXX_PRIVACY_IDENTITY_REGISTRY_V1")
        );
        assertEq(
            registry.outputNoteDataSuite(),
            "ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1"
        );
    }

    function test_runtimeSizeUnderEip170() public view {
        assertLt(address(registry).code.length, 24_576, "registry must fit EIP-170");
    }
}
