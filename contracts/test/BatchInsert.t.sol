// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {PoseidonFieldLib} from "../src/libraries/PoseidonFieldLib.sol";

contract BatchInsertHarness is ShieldedPool {
    function initialize() external {
        noteCommitmentEmptyHashes[0] = 0;
        for (uint256 i = 1; i < 32; ++i) {
            noteCommitmentEmptyHashes[i] = PoseidonFieldLib.merkleHash(
                noteCommitmentEmptyHashes[i - 1], noteCommitmentEmptyHashes[i - 1]
            );
        }
        currentNoteCommitmentRoot = PoseidonFieldLib.merkleHash(
            noteCommitmentEmptyHashes[31], noteCommitmentEmptyHashes[31]
        );
    }
    function insertSingle(uint256 c) external { _insertNoteCommitment(c); }
    function insertBatch3(uint256[3] memory cs) external { _insertNoteCommitmentBatch3(cs); }
    function getRoot() external view returns (uint256) { return currentNoteCommitmentRoot; }
    function getNextLeafIndex() external view returns (uint256) { return nextLeafIndex; }
    function getFilled(uint256 level) external view returns (uint256) { return filledNoteCommitmentSubtrees[level]; }
}

contract BatchInsertTest is Test {
    function _runCase(uint256 startIdx) internal {
        BatchInsertHarness a = new BatchInsertHarness();
        BatchInsertHarness b = new BatchInsertHarness();
        a.initialize();
        b.initialize();

        for (uint256 i; i < startIdx; ++i) {
            uint256 dummy = uint256(keccak256(abi.encode("dummy", i))) % PoseidonFieldLib.FIELD_MODULUS;
            a.insertSingle(dummy);
            b.insertSingle(dummy);
        }
        assertEq(a.getRoot(), b.getRoot(), string(abi.encodePacked("pre-state root mismatch @startIdx=", vm.toString(startIdx))));

        uint256[3] memory c;
        c[0] = uint256(keccak256(abi.encode("c0", startIdx))) % PoseidonFieldLib.FIELD_MODULUS;
        c[1] = uint256(keccak256(abi.encode("c1", startIdx))) % PoseidonFieldLib.FIELD_MODULUS;
        c[2] = uint256(keccak256(abi.encode("c2", startIdx))) % PoseidonFieldLib.FIELD_MODULUS;

        a.insertBatch3(c);
        b.insertSingle(c[0]);
        b.insertSingle(c[1]);
        b.insertSingle(c[2]);

        assertEq(a.getRoot(), b.getRoot(), string(abi.encodePacked("post-insertion root mismatch @startIdx=", vm.toString(startIdx))));
        assertEq(a.getNextLeafIndex(), b.getNextLeafIndex(), string(abi.encodePacked("nextLeafIndex mismatch @startIdx=", vm.toString(startIdx))));
        for (uint256 h; h < 32; ++h) {
            assertEq(
                a.getFilled(h),
                b.getFilled(h),
                string(abi.encodePacked("filled mismatch @startIdx=", vm.toString(startIdx), " level=", vm.toString(h)))
            );
        }
    }

    function test_BatchEquiv_Index0()  public { _runCase(0); }
    function test_BatchEquiv_Index1()  public { _runCase(1); }
    function test_BatchEquiv_Index2()  public { _runCase(2); }
    function test_BatchEquiv_Index3()  public { _runCase(3); }
    function test_BatchEquiv_Index15() public { _runCase(15); }
    function test_BatchEquiv_Index16() public { _runCase(16); }
    function test_BatchEquiv_Index17() public { _runCase(17); }

    // Incremental equivalence sweep: grow two trees in lockstep -- one always via
    // _insertNoteCommitmentBatch3, one via three sequential _insertNoteCommitment
    // -- and assert identical root, nextLeafIndex, and all 32 filledSubtrees after
    // every batch. Back-to-back 3-leaf batches start at indices 0,3,6,... which
    // cover every binary alignment (gcd(3,2^k)=1) and straddle the 128/256/512
    // power-of-two boundaries (batches 42/85/170), exercising deep multi-level
    // carries. Bounded to stay under the default 2^30 test gas limit; the per-
    // level loop body is uniform across heights, so higher indices reduce to the
    // single-insert path already exercised here.
    function test_BatchEquiv_Incremental() public {
        BatchInsertHarness a = new BatchInsertHarness();
        BatchInsertHarness b = new BatchInsertHarness();
        a.initialize();
        b.initialize();

        for (uint256 k; k < 171; ++k) {
            uint256[3] memory c;
            c[0] = uint256(keccak256(abi.encode("c0", k))) % PoseidonFieldLib.FIELD_MODULUS;
            c[1] = uint256(keccak256(abi.encode("c1", k))) % PoseidonFieldLib.FIELD_MODULUS;
            c[2] = uint256(keccak256(abi.encode("c2", k))) % PoseidonFieldLib.FIELD_MODULUS;

            a.insertBatch3(c);
            b.insertSingle(c[0]);
            b.insertSingle(c[1]);
            b.insertSingle(c[2]);

            assertEq(a.getRoot(), b.getRoot(), string(abi.encodePacked("root mismatch @batch=", vm.toString(k))));
            assertEq(
                a.getNextLeafIndex(),
                b.getNextLeafIndex(),
                string(abi.encodePacked("nextLeafIndex mismatch @batch=", vm.toString(k)))
            );
            for (uint256 h; h < 32; ++h) {
                assertEq(
                    a.getFilled(h),
                    b.getFilled(h),
                    string(abi.encodePacked("filled mismatch @batch=", vm.toString(k), " level=", vm.toString(h)))
                );
            }
        }
    }
}
