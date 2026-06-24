// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "contracts/src/ShieldedPool.sol";
import {ShieldedPoolInstallHarness} from "contracts/script/InstallSystemContracts.s.sol";
import {PoseidonFieldLib} from "contracts/src/libraries/PoseidonFieldLib.sol";
import {DemoShieldedPool} from "../src/DemoShieldedPool.sol";
import {RecipientRegistry} from "../src/RecipientRegistry.sol";

contract DemoShieldedPoolTest is Test {
    function testConstructorMatchesInstallerInitialize() public {
        DemoShieldedPool demo = new DemoShieldedPool();

        address harnessAddress = address(0x818200);
        vm.etch(harnessAddress, type(ShieldedPoolInstallHarness).runtimeCode);
        ShieldedPoolInstallHarness(harnessAddress).initialize();

        (uint256 expectedNoteRoot, uint256 expectedAuthRoot) =
            ShieldedPoolInstallHarness(harnessAddress).getCurrentRoots();
        (uint256 actualNoteRoot, uint256 actualAuthRoot) = demo.getCurrentRoots();

        assertEq(actualNoteRoot, expectedNoteRoot);
        assertEq(actualAuthRoot, expectedAuthRoot);
        assertTrue(demo.isAcceptedNoteCommitmentRoot(actualNoteRoot));
        assertTrue(demo.isAcceptedAuthPolicyRoot(actualAuthRoot));
    }

    function testFirstAuthPolicyUsesSlotOne() public {
        DemoShieldedPool demo = new DemoShieldedPool();
        address user = address(0xABCD);

        vm.prank(user);
        uint256 leafPosition = demo.setAuthPolicy(0x1234, 0x5678, 0x9abc);

        assertEq(leafPosition, 1);

        (bool registered, ShieldedPool.UserEntry memory entry) = demo.getAuthPolicyEntry(user);
        assertTrue(registered);
        assertEq(entry.leafPosition, 1);
        assertEq(entry.ownerNullifierKeyHash, 0x1234);
        assertEq(entry.noteSecretSeedHash, 0x5678);
        assertEq(entry.policySetCommitment, 0x9abc);
    }

    function testDepositUsesSeededNoteTree() public {
        DemoShieldedPool demo = new DemoShieldedPool();
        (uint256 noteRootBefore,) = demo.getCurrentRoots();
        uint256 ownerCommitment = uint256(keccak256("demo owner commitment")) % PoseidonFieldLib.FIELD_MODULUS;

        vm.deal(address(this), 1 ether);
        demo.deposit{value: 1 ether}(address(0), 1 ether, ownerCommitment, "demo note");

        (uint256 noteRootAfter,) = demo.getCurrentRoots();
        assertTrue(noteRootAfter != noteRootBefore);
        assertTrue(demo.isAcceptedNoteCommitmentRoot(noteRootBefore));
        assertEq(address(demo).balance, 1 ether);
    }
}

contract RecipientRegistryTest is Test {
    RecipientRegistry internal registry;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    bytes internal mlKemKey;
    bytes32 internal x25519Key = keccak256("alice x25519 key");

    function setUp() public {
        registry = new RecipientRegistry();
        mlKemKey = new bytes(1184);
    }

    function testPublishRecipient() public {
        vm.prank(alice);
        registry.publishRecipient(0x1234, mlKemKey, x25519Key, 1);

        (bool registered, RecipientRegistry.Recipient memory recipient) = registry.getRecipient(alice);
        assertTrue(registered);
        assertEq(recipient.ownerNullifierKeyHash, 0x1234);
        assertEq(recipient.mlKem768PublicKey, mlKemKey);
        assertEq(recipient.x25519PublicKey, x25519Key);
        assertEq(recipient.metadataVersion, 1);
        assertEq(registry.ownerOf(0x1234), alice);
    }

    function testPublishRecipientUpdatesDeliveryMetadata() public {
        bytes memory newMlKemKey = new bytes(1184);
        newMlKemKey[0] = 0x42;

        vm.startPrank(alice);
        registry.publishRecipient(0x1234, mlKemKey, x25519Key, 1);
        registry.publishRecipient(0x1234, newMlKemKey, keccak256("new x25519 key"), 2);
        vm.stopPrank();

        (, RecipientRegistry.Recipient memory recipient) = registry.getRecipient(alice);
        assertEq(recipient.ownerNullifierKeyHash, 0x1234);
        assertEq(recipient.mlKem768PublicKey, newMlKemKey);
        assertEq(recipient.x25519PublicKey, keccak256("new x25519 key"));
        assertEq(recipient.metadataVersion, 2);
        assertEq(registry.ownerOf(0x1234), alice);
    }

    function testPublishRecipientRejectsChangedOwnerHash() public {
        vm.startPrank(alice);
        registry.publishRecipient(0x1234, mlKemKey, x25519Key, 1);
        vm.expectRevert(RecipientRegistry.OwnerNullifierKeyHashImmutable.selector);
        registry.publishRecipient(0x5678, mlKemKey, keccak256("alice key 2"), 2);
        vm.stopPrank();
    }

    function testPublishRecipientRejectsDuplicateOwnerHash() public {
        vm.prank(alice);
        registry.publishRecipient(0x1234, mlKemKey, x25519Key, 1);

        vm.prank(bob);
        vm.expectRevert(RecipientRegistry.DuplicateOwnerNullifierKeyHash.selector);
        registry.publishRecipient(0x1234, mlKemKey, keccak256("bob key"), 1);
    }

    function testPublishRecipientRejectsReservedOwnerHash() public {
        vm.expectRevert(RecipientRegistry.ReservedOwnerNullifierKeyHash.selector);
        registry.publishRecipient(0, mlKemKey, x25519Key, 1);

        vm.expectRevert(RecipientRegistry.ReservedOwnerNullifierKeyHash.selector);
        registry.publishRecipient(
            PoseidonFieldLib.dummyOwnerNullifierKeyHash(), mlKemKey, x25519Key, 1
        );
    }

    function testPublishRecipientRejectsNonCanonicalOwnerHash() public {
        vm.expectRevert(RecipientRegistry.FieldElementNotCanonical.selector);
        registry.publishRecipient(PoseidonFieldLib.FIELD_MODULUS, mlKemKey, x25519Key, 1);
    }

    function testPublishRecipientRejectsInvalidEncryptionKeys() public {
        vm.expectRevert(RecipientRegistry.InvalidMlKemPublicKey.selector);
        registry.publishRecipient(0x1234, new bytes(1183), x25519Key, 1);

        vm.expectRevert(RecipientRegistry.InvalidX25519PublicKey.selector);
        registry.publishRecipient(0x1234, mlKemKey, bytes32(0), 1);
    }

    function testClearRecipient() public {
        vm.startPrank(alice);
        registry.publishRecipient(0x1234, mlKemKey, x25519Key, 1);
        registry.clearRecipient();
        vm.stopPrank();

        (bool registered, RecipientRegistry.Recipient memory recipient) = registry.getRecipient(alice);
        assertFalse(registered);
        assertEq(recipient.ownerNullifierKeyHash, 0);
        assertEq(registry.ownerOf(0x1234), address(0));
    }
}
