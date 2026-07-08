---
eip: TBD
title: Application-Layer Private ETH and ERC-20 Transfers
description: Private ETH and ERC-20 transfers with shared pool semantics, pluggable auth, a canonical privacy identity registry, encrypted note delivery, and optional policy verifier hooks.
author: Tom Lehman (@RogerPodacter)
discussions-to: TBD
status: Draft
type: Standards Track
category: ERC
created: 2026-07-01
requires: 20
---

## Abstract

This ERC defines a standard for private ETH and ERC-20 transfers using deployed shielded pools. A conforming pool supports deposits, private transfers, withdrawals, note commitments, nullifiers, root histories, pool proof verification, and pluggable spend authorization.

The ERC also standardizes the interoperability surface around those pools: a chain-wide canonical privacy identity registry, auth-verifier dispatch, ABI-encoded post-quantum encrypted note delivery through `outputNoteData`, and optional policy verifier hooks for pool-specific checks.

## Motivation

Private-transfer pool innovation benefits from shared standards and reusable infrastructure. A team deploying a new shielded pool does not need to redesign note semantics, nullifiers, authorization, receive-key discovery, encrypted note delivery, or proof integration from scratch.

This ERC provides a shared playbook for deploying shielded pools as ordinary Ethereum contracts. It is opinionated about the parts that need to line up for wallets, provers, indexers, and applications to interoperate, while leaving deployments free to choose their assets, liquidity, relayers, routers, frontends, and optional policy profile.

The ERC also enables reuse of actual artifacts and infrastructure. Pools can share the canonical pool relation, canonical pool verifier, trusted setup, auth profiles, canonical privacy identity registry, receive-key publication flow, encrypted `outputNoteData` format, and wallet/indexer implementation work. Standardizing those pieces lets new deployments build on existing work instead of creating incompatible one-off systems.

The authorization model separates note validity from user authorization. The pool relation can stay stable while wallets and applications add auth methods through pluggable auth verifiers.

The default receive and delivery flow is also opinionated. Recipients publish registry-backed privacy identity and post-quantum receive-key material, and senders deliver recoverable notes through ABI-encoded ML-KEM encrypted `outputNoteData`.

Users can unshield to a contract, let the contract perform public Ethereum actions such as swaps, payments, or bridge deposits, and reshield the resulting asset in the same transaction. The same mechanism can move value atomically between pools.

Policy-free pools are first-class conforming pools. For deployments that want compliance, credential, membership, disclosure, pending-deposit, or other pool-specific checks, this ERC defines an optional policy verifier hook so those profiles can reuse the same pool, auth, and verifier conventions.

This ERC uses the note, nullifier, and split-authorization ideas from EIP-8182 to specify a reusable deployed-contract profile for independently deployed privacy pools.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

This document is self-contained. References to related protocol proposals are non-normative unless this ERC explicitly restates the requirement.

### 1. Overview

This ERC defines:

1. A deployed private-transfer pool, implemented as an ordinary smart contract.
2. The pool state, hash domains, note/nullifier formulas, deposit rules, private-transfer rules, withdrawal rules, and canonical registry rules.
3. A split-proof authorization model in which the pool verifies private-transfer validity and dispatches user authorization to pluggable auth verifiers.
4. Deployed-pool intent binding.
5. A chain-wide canonical privacy identity registry for shared identity, auth-method, and receive-key discovery.
6. A default encrypted `outputNoteData` envelope and note-payload format.
7. Note discovery, trial decryption, and note acceptance conventions.
8. An optional policy verifier profile.

The base profile focuses on pool execution, authorization, registry identity, note delivery, and wallet interoperability. Transaction-submitter privacy, relayer markets, and compliance disclosure schemes are separate application or profile choices.

A policy-free pool is a conforming pool. Policy verifier support is a standardized hook for pool profiles that require additional operation-level checks. The empty policy-data convention is `policyData = 0x`, `policyDataHash = uint256(keccak256(0x)) mod p`, and `policyOperationDataHash = 0`.

### 2. Terminology

* **Private-transfer pool**: A deployed contract implementing this ERC's pool profile.
* **Pool identity**: The pair `(chainId, poolAddress)`, where `chainId` is the execution chain ID and `poolAddress` is the deployed pool contract address.
* **Canonical privacy identity registry**: The singleton registry on a chain that binds an Ethereum address to private-transfer identity material, auth-method state, and receive-key material.
* **Registry identity**: The tuple `(chainId, account)` in the canonical privacy identity registry.
* **Note**: A shielded UTXO-like object represented on-chain by a final `noteCommitment`.
* **Nullifier**: The public spent-note marker for one real input note.
* **Phantom nullifier**: The public spent-input marker for one phantom input slot.
* **Phantom input**: A dummy input slot used to maintain constant input arity.
* **Dummy output**: A dummy output slot used to maintain constant output arity.
* **Owner nullifier key**: The note owner's non-rotatable hidden note-ownership key.
* **ownerNullifierKeyHash**: The Poseidon hash of the owner nullifier key.
* **leafIndex**: The final note-tree leaf index assigned by the pool when the note is inserted.
* **Output note data**: Opaque per-output bytes emitted by the pool for wallet-level note delivery.
* **Output binding**: `poseidon(OUTPUT_BINDING_DOMAIN, noteBodyCommitment, outputNoteDataHash)`.
* **Canonical pool verifier**: The singleton stateless verifier contract used by every conforming pool on a chain to verify pool proofs.
* **Auth verifier**: The Solidity contract address that verifies auth proofs for one specific auth relation.
* **Auth method**: A user-side authorization method — a `(authVerifier, authDataCommitment)` binding encoded in one `policyCommitment`, included in a user's registry-level `policySetCommitment`. This is user authorization, chosen and registered by the user; it is distinct from the pool-level policy verifier below. The registry field and circuit-signal names retain the `policy*` prefix (`policyCommitment`, `policySetCommitment`, `POLICY_SET_DEPTH`) for the structural Merkle set that holds a user's auth methods; those names do not denote pool-level policy.
* **Policy data**: Opaque bytes supplied to a pool-selected policy verifier for compliance, credential, membership, disclosure, or other pool-level policy checks. Policy data is a pool-wide rule input, not a user auth method.
* **Policy verifier**: A Solidity contract address selected by a pool profile to verify pool-level policy data for a policy operation digest. A pool-wide rule, distinct from a user's auth methods.
* **Receive key**: Public ML-KEM-768 encryption material used by senders to encrypt output note payloads for a recipient.
* **Receive profile**: The registry-level recipient data needed to deliver encrypted private notes to an Ethereum address.
* **Identity entry**: The validity-critical registry entry containing `ownerNullifierKeyHash`, `noteSecretSeedHash`, `policySetCommitment`, and `leafPosition`.
* **Receive entry**: The delivery-only registry entry containing ML-KEM receive key material and a metadata version.
* **Encrypted note envelope**: The bytes supplied as `outputNoteData` under the default format defined by this ERC.

### 3. Cryptographic Conventions

The base pool uses BN254 scalar arithmetic, Poseidon2 hashes, LSB-first Merkle paths, domain-separated note/nullifier formulas, and a deployed-pool transaction intent digest. The exact constants and formulas are defined in Section 15.

Pool contracts, the canonical pool verifier, pool circuits, auth verifiers, and policy verifiers MUST use the Section 15 values wherever this ERC references `p`, `poseidon(...)`, domain constants, tree roots, note commitments, nullifiers, output bindings, or intent digests.

### 4. Pool Contract Interface

A conforming pool MUST implement:

```solidity
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
```

The pool introspection functions MUST behave as follows:

* `poseidonParametersDigest()` returns the SHA-256 digest of the Poseidon2 parameter asset used by this ERC.
* `outputNoteDataSuite()` returns `"ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1"` and MUST equal `IERCXXXXPrivacyIdentityRegistry(CANONICAL_PRIVACY_REGISTRY_ADDRESS).outputNoteDataSuite()`.
* `policyVerifier()` returns the pool-selected policy verifier, or `address(0)` if the pool profile requires no policy checks.
* `policyAppliesToOperations()` returns a bitset over `POLICY_APPLIES_DEPOSIT`, `POLICY_APPLIES_TRANSFER`, `POLICY_APPLIES_WITHDRAWAL`, and `POLICY_APPLIES_CUSTOM`.

Every conforming pool MUST use `CANONICAL_PRIVACY_REGISTRY_ADDRESS` for identity roots, identity entries, receive entries, and registry suite checks.

`getCurrentRoots()` MUST return the pool's current note-commitment root and `IERCXXXXPrivacyIdentityRegistry(CANONICAL_PRIVACY_REGISTRY_ADDRESS).getCurrentIdentityRoot()`.

Recipient profile discovery uses `getPrivacyProfile(recipient)` on the canonical privacy identity registry for `chainId`.

A conforming pool MUST emit:

```solidity
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
```

Admin, upgrade, pause, and policy controls are outside the base pool interface. A pool satisfies this ERC while its execution, proof, event, and introspection behavior matches the requirements below. Deployment controls are trust assumptions for users and wallets, not part of the base interoperability surface.

### 5. Pool State

A conforming pool MUST maintain:

* a depth-32 append-only note commitment tree,
* a note commitment root history of `NOTE_COMMITMENT_ROOT_HISTORY_SIZE` roots,
* a nullifier set,
* an intent replay ID set, and
* a `nextLeafIndex` note-tree counter.

The note commitment tree assigns `uint32` leaf indices sequentially from `0`. `nextLeafIndex` has initial value `0`. The pool MUST revert if `nextLeafIndex + 3 > 2^32` before a `transact` insertion or `nextLeafIndex + 1 > 2^32` before a `deposit` insertion. On each `transact` and each `deposit`, the pool MUST push the pre-insertion note-commitment root into the note-root history before writing new leaves. The pool MUST accept the current note-commitment root and any historical note-commitment root still present in the `NOTE_COMMITMENT_ROOT_HISTORY_SIZE` circular buffer.

Pools MUST NOT maintain registry identity state, receive-entry state, policy-set state, or owner-hash uniqueness state. Those are canonical privacy registry state.

### 6. Privacy Identity Registry

The canonical privacy identity registry is a singleton contract with one canonical instance per chain. It maintains validity-critical identity state and delivery-only receive state for Ethereum addresses. The identity plane is part of the pool validity relation. The receive plane is for wallet delivery and MUST NOT be included in the identity leaf opened by the pool circuit.

A conforming registry MUST satisfy this ERC's identity registration, identity root acceptance, receive-entry, and event semantics.

A conforming pool MUST use the canonical privacy identity registry at `CANONICAL_PRIVACY_REGISTRY_ADDRESS`. The account at that address MUST have `extcodehash == CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH`. Pools that use another registry are outside this ERC profile, even if that registry implements the same interface.

The registry MUST implement:

```solidity
interface IERCXXXXPrivacyIdentityRegistry {
    struct IdentityEntry {
        uint32 leafPosition;
        uint256 ownerNullifierKeyHash;
        uint256 noteSecretSeedHash;
        uint256 policySetCommitment;
    }

    struct ReceiveEntry {
        bytes mlKem768PublicKey;
        uint32 metadataVersion;
    }

    event IdentitySet(
        address indexed user,
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment,
        uint32 leafPosition,
        uint256 leafValue,
        uint256 postUpdateIdentityRoot
    );

    event ReceiveProfileSet(
        address indexed user,
        bytes mlKem768PublicKey,
        uint32 metadataVersion
    );

    event ReceiveProfileCleared(
        address indexed user,
        uint32 metadataVersion
    );

    function setIdentity(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment
    ) external returns (uint32 leafPosition);

    function setReceiveProfile(
        bytes calldata mlKem768PublicKey,
        uint32 metadataVersion
    ) external;

    function setFullProfile(
        uint256 ownerNullifierKeyHash,
        uint256 noteSecretSeedHash,
        uint256 policySetCommitment,
        bytes calldata mlKem768PublicKey,
        uint32 metadataVersion
    ) external returns (uint32 leafPosition);

    function clearReceiveProfile(uint32 metadataVersion) external;

    function getIdentityEntry(address user)
        external
        view
        returns (bool registered, IdentityEntry memory entry);

    function getReceiveEntry(address user)
        external
        view
        returns (bool registered, ReceiveEntry memory entry);

    function getPrivacyProfile(address user)
        external
        view
        returns (
            bool identityRegistered,
            IdentityEntry memory identity,
            bool receiveRegistered,
            ReceiveEntry memory receive
        );

    function getCurrentIdentityRoot() external view returns (uint256);
    function isAcceptedIdentityRoot(uint256 root) external view returns (bool);
    function ercXXXXPrivacyRegistryId() external pure returns (bytes32);
    function outputNoteDataSuite() external pure returns (string memory);
}
```

The privacy identity registry tree assigns `leafPosition` sequentially from `1`. `nextLeafPosition` has initial value `1`. The registry MUST reject a first identity registration if `nextLeafPosition >= 2^32` before assignment. Position `0` is reserved as the unassigned sentinel. Each identity leaf value is:

```text
poseidon(IDENTITY_LEAF_DOMAIN, uint160(user), ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment)
```

The identity root history is block-based. For window `W = IDENTITY_ROOT_HISTORY_BLOCKS`, the registry maintains a ring buffer of `W + 1` `(root, blockNumber)` pairs. The extra slot prevents a mutation in block `N + W` from overwriting a root that is still within the acceptance window. On the first identity mutation in block `N`, the registry MUST snapshot the root accepted at the start of block `N` at position `N mod (W + 1)`. Later identity mutations in the same block MUST NOT create additional history entries. The current identity root is always accepted. A historical identity root is accepted only if a stored pair has `storedRoot == root` and `block.number - storedBlockNumber <= W`. Root `0` MUST never be accepted. Intermediate same-block roots are not retained once later same-block mutations occur.

`setIdentity` is called by `msg.sender` to register or update their identity leaf.

The caller computes `policySetCommitment` off-chain as the depth-`POLICY_SET_DEPTH` sparse Merkle root over their currently active `policyCommitment` values. Each `policyCommitment` is:

```text
poseidon(POLICY_COMMITMENT_DOMAIN, uint160(authVerifier), authDataCommitment, registrationBlinder)
```

`setIdentity` does not expose individual `policyCommitment` values, `authVerifier` values, `authDataCommitment` values, or `registrationBlinder` values.

`setIdentity` MUST reject:

* `ownerNullifierKeyHash >= p`,
* `noteSecretSeedHash >= p`,
* `policySetCommitment >= p`,
* `ownerNullifierKeyHash == 0`,
* `ownerNullifierKeyHash == DUMMY_OWNER_NULLIFIER_KEY_HASH`, or
* `noteSecretSeedHash == 0`.

On the first successful identity registration from an address, the registry MUST:

* require that the `ownerNullifierKeyHash` is not already registered by another address in that registry,
* assign the next available nonzero `leafPosition`,
* lock the address to that `ownerNullifierKeyHash`,
* store `noteSecretSeedHash` and `policySetCommitment`, and
* set the registry owner-hash uniqueness index.

On later identity updates from the same address, the registry MUST:

* require the same `ownerNullifierKeyHash`,
* keep the same `leafPosition`, and
* update only `noteSecretSeedHash` and `policySetCommitment`.

The registry MUST compute the identity leaf, reject `leafValue == 0`, snapshot the pre-update identity root according to this section, write the leaf, emit `IdentitySet`, and return `leafPosition`.

To revoke all active policies, a caller submits `policySetCommitment` equal to the empty depth-`POLICY_SET_DEPTH` policy-set root. The registry does not special-case that value; the pool circuit enforces that any spend's `policyCommitment` is nonzero and is a member of `policySetCommitment`. Against an empty-set root, no spend can satisfy that constraint. Revocation and seed rotation take full effect for every conforming pool only after the prior identity root ages out of the registry root-history window.

Slot assignment within the policy-set tree is caller-defined. Duplicate `policyCommitment` leaves are permitted but do not add authorization power. Revoking an auth method requires a new `policySetCommitment` that excludes every slot containing that method's `policyCommitment`; leaving a duplicate behind leaves the method effective.

Spending through an auth method requires enough metadata to reproduce that method's `policyCommitment` and its policy-set slot position. Losing this metadata can make the method unusable until the user registers a replacement policy set. Note ownership is unaffected because notes bind to `ownerNullifierKeyHash`, not to a specific auth method.

`setReceiveProfile` MUST reject `mlKem768PublicKey.length != 1184`. Receive-entry updates do not change the identity leaf, identity root, spend validity, `ownerNullifierKeyHash`, `noteSecretSeedHash`, or `policySetCommitment`. The registry MUST store and return the latest receive entry for `msg.sender`, and MUST emit `ReceiveProfileSet`.

`setFullProfile` MUST apply `setIdentity` and `setReceiveProfile` semantics atomically. `clearReceiveProfile(metadataVersion)` MUST clear only the caller's receive entry and emit `ReceiveProfileCleared`. Clearing a receive entry prevents future default registry discovery; it does not invalidate already-created notes, old encrypted payloads, or the caller's identity entry.

`ercXXXXPrivacyRegistryId()` MUST return `bytes32(keccak256("ERCXXXX_PRIVACY_IDENTITY_REGISTRY_V1"))`. `outputNoteDataSuite()` MUST return `"ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1"`.

### 7. Execution Rules

`transact` and `deposit` MUST be non-reentrant.

#### 7.1 `transact`

On each `transact` call, the pool MUST:

1. Require `executionChainId == block.chainid`.
2. Require `poolAddress == uint160(address(this))`.
3. Require `authorizedSubmitter < 2^160` and `downstreamActionCommitment < p`.
4. If `downstreamActionCommitment != 0`, require `authorizedSubmitter != 0`.
5. If `authorizedSubmitter != 0`, `transact` MUST require `msg.sender == address(uint160(authorizedSubmitter))` before verifying proofs, marking nullifiers, consuming the intent replay ID, executing public asset movement, or inserting output commitments. If `authorizedSubmitter == 0`, any caller MAY submit.
6. Require `validUntilSeconds > 0`.
7. Require `block.timestamp <= validUntilSeconds`.
8. Require `validUntilSeconds <= block.timestamp + MAX_INTENT_LIFETIME`.
9. Require `noteCommitmentRoot` to be the current note root or an accepted historical note root.
10. Require `identityRoot` to be nonzero and accepted by `IERCXXXXPrivacyIdentityRegistry(CANONICAL_PRIVACY_REGISTRY_ADDRESS).isAcceptedIdentityRoot(identityRoot)`.
11. Require `nullifier0 != nullifier1`.
12. Require `publicAmountOut < 2^248`.
13. Require `publicRecipientAddress < 2^160`.
14. Require `publicTokenAddress < 2^160`.
15. Require `poolAddress < 2^160`.
16. Require `authVerifier < 2^160` and `authVerifier != 0`.
17. Require `policyOperationDataHash < p`.
18. Require `policyDataHash < p`.
19. Require `validUntilSeconds < 2^32`.
20. Require `executionChainId < 2^32`.
21. Require `uint256(keccak256(policyData)) mod p == policyDataHash`.
22. For each output slot `i`, require `uint256(keccak256(outputNoteData_i)) mod p == outputNoteDataHash_i`.
23. Verify `poolProof` by `staticcall` to `CANONICAL_POOL_VERIFIER_ADDRESS` with `publicInputs`.
24. Verify `authProof` by `staticcall` to `authVerifier`.
25. Apply Section 16.1 for the selected transfer or withdrawal operation.
26. Require both nullifiers to be unspent, then mark them spent.
27. Require `intentReplayId` to be unused, then mark it used.
28. Execute the public asset movement.
29. Assign `leafIndex0 = nextLeafIndex`; require `leafIndex0 + 3 <= 2^32`.
30. Compute final commitments:

    ```text
    noteCommitment0 = poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitment0, leafIndex0)
    noteCommitment1 = poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitment1, leafIndex0 + 1)
    noteCommitment2 = poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitment2, leafIndex0 + 2)
    ```

31. Require all three final commitments to be nonzero.
32. Push the pre-insertion note root to note-root history.
33. Insert all three commitments in order.
34. Emit `ShieldedPoolTransact`.

For public asset movement:

* If `publicAmountOut > 0`, the call is a withdrawal. The pool MUST require `publicRecipientAddress != 0`. If `publicTokenAddress == 0`, it MUST send ETH to `publicRecipientAddress`. Otherwise it MUST transfer `publicAmountOut` of the ERC-20 at `publicTokenAddress` to `publicRecipientAddress`.
* If `publicAmountOut == 0`, the call is a private transfer. The pool MUST require `publicRecipientAddress == 0` and `publicTokenAddress == 0`.

`authorizedSubmitter` and `downstreamActionCommitment` exist because a withdrawal proof is otherwise bearer authorization. A withdrawal intent authorizes moving a public asset amount to `publicRecipientAddress`; once the proof and authorization are visible in the mempool, any observer could submit the withdrawal leg directly. That decouples the withdrawal from an intended downstream action and can strand funds, particularly for ERC-20 assets, which have no receiver hook to re-attach the withdrawal to a follow-on step. Setting `authorizedSubmitter` to a nonzero address makes the authorization named rather than bearer: only that address may call `transact` for the intent. `downstreamActionCommitment` is an opaque field that lets the user's authorization bind a router's downstream action plan without the pool interpreting it. Because a bound downstream action is meaningful only when a specific submitter is trusted to carry it out, `downstreamActionCommitment != 0` requires `authorizedSubmitter != 0`.

`transact` MUST be non-payable.

#### 7.2 Pool Proof Verification

`poolProof` MUST prove the relation in Section 8.

A conforming pool MUST verify pool proofs by `staticcall` to `CANONICAL_POOL_VERIFIER_ADDRESS`.

The canonical pool verifier is the immutable stateless Groth16 verifier for this ERC's pool relation. It embeds the canonical verification key published with this ERC.

The canonical pool verifier MUST implement, using the `PublicInputs` struct defined in Section 4:

```solidity
interface IERCXXXXPoolVerifier {
    function verifyPoolProof(
        bytes calldata proof,
        PublicInputs calldata publicInputs
    ) external view returns (bool);
}
```

The pool proof system is Groth16 over BN254. The proof encoding MUST be exactly 256 bytes:

```text
A.x || A.y || B.x.c1 || B.x.c0 || B.y.c1 || B.y.c0 || C.x || C.y
```

where each coordinate is encoded as a 32-byte big-endian integer.

The pool MUST call `verifyPoolProof` with `proof = poolProof` and the `PublicInputs` value supplied to `transact`. The verifier interprets `PublicInputs` fields in declaration order.

The pool MUST treat any of the following as pool proof failure:

* the `staticcall` reverts,
* returndata length is not exactly 32 bytes,
* the decoded boolean is `false`,
* malformed proof encoding,
* any public input `>= p`,
* any invalid curve point or subgroup element, or
* pairing-equation failure.

#### 7.3 `deposit`

On each `deposit` call, the pool MUST:

1. Require `amount > 0`.
2. Require `amount < 2^248`.
3. Require `ownerCommitment != 0`.
4. Require `ownerCommitment < p`.
5. Compute `outputNoteDataHash = uint256(keccak256(outputNoteData)) mod p`.
6. Apply Section 16.1 for the deposit operation.
7. If `token == address(0)`, require `msg.value == amount`.
8. If `token != address(0)`, require `msg.value == 0`, pull exactly `amount` of the ERC-20 from `msg.sender`, and verify by balance delta that the pool received exactly `amount`.
9. Assign `leafIndex = nextLeafIndex`; require `leafIndex + 1 <= 2^32`.
10. Compute `noteBodyCommitment` and final `noteCommitment = poseidon(NOTE_COMMITMENT_DOMAIN, block.chainid, uint160(address(this)), noteBodyCommitment, leafIndex)`.
11. Require `noteCommitment != 0`.
12. Push the pre-insertion note root to note-root history.
13. Insert the final commitment.
14. Emit `ShieldedPoolDeposit`.

The pool MUST NOT parse or validate `outputNoteData` in `deposit`.

#### 7.4 ERC-20 Semantics

ERC-20 calls in both `transact` and `deposit` MUST use these semantics:

* `balanceOf(address(this))` MUST be executed via `staticcall`, MUST not revert, and MUST return exactly 32 bytes.
* `transferFrom(msg.sender, address(this), amount)` and `transfer(recipient, amount)` MUST not revert and MUST satisfy one of:
  * returndata length is `0` and the target account has nonzero code length, or
  * returndata length is exactly 32 bytes decoding to `true`.
* Any other returndata shape, empty returndata from an account with zero code length, or a decoded `false` MUST be treated as failure.

Fee-on-transfer and rebasing tokens are incompatible. Such tokens MUST NOT be deposited.

#### 7.5 Auth Verifier Dispatch

Auth verifiers MUST implement:

```solidity
interface IERCXXXXAuthVerifier {
    function verifyAuth(
        bytes calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}
```

`verifyAuth` MUST be `view`: the pool dispatches it with `staticcall`, so any auth verifier that attempts to modify state reverts and is treated as an auth proof failure.

The pool MUST call `verifyAuth` using `staticcall` with:

```text
publicInputs = abi.encode(blindedAuthCommitment, transactionIntentDigest)
```

The pool MUST treat any of the following as auth proof failure:

* `authVerifier` has no deployed code,
* the `staticcall` reverts,
* returndata length is not exactly 32 bytes, or
* the decoded boolean is `false`.

### 8. Pool Circuit Relation

The pool circuit MUST satisfy the following relation. Witnesses are not limited to the values named in step 1; they include all private values needed to satisfy this section.

1. Witness `authorizingAddress`, `ownerNullifierKeyHash`, `noteSecretSeedHash`, `policySetCommitment`, `leafPosition`, and a depth-32 privacy-registry identity Merkle path.
2. Enforce `authorizingAddress < 2^160`, `leafPosition < 2^32`, `ownerNullifierKeyHash < p`, `noteSecretSeedHash < p`, and `policySetCommitment < p`.
3. Enforce `ownerNullifierKeyHash != 0`, `ownerNullifierKeyHash != DUMMY_OWNER_NULLIFIER_KEY_HASH`, and `noteSecretSeedHash != 0`.
4. Prove that the registry identity leaf opened against `identityRoot` at `leafPosition` equals:

    ```text
    poseidon(IDENTITY_LEAF_DOMAIN, uint160(authorizingAddress), ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment)
    ```

5. Recompute `policyCommitment` and enforce `policyCommitment != 0`.
6. Prove `policyCommitment` membership in `policySetCommitment` using a witnessed policy-set slot position `< 2^POLICY_SET_DEPTH` and a depth-`POLICY_SET_DEPTH` sparse Merkle path.
7. Recompute `blindedAuthCommitment`.
8. Recompute `transactIntentFieldsHash` and `transactionIntentDigest`.
9. Derive `intentReplayId`.
10. Validate input note ownership and nullifiers.
11. Validate output note-body commitments and output bindings.
12. Enforce value conservation and token consistency.

The circuit MUST treat `poolAddress` as a public input, constrain it to `< 2^160`, and absorb it into `transactionIntentDigest` as specified in Section 15.6. The pool contract separately enforces `poolAddress == uint160(address(this))`.

The circuit MUST treat `authVerifier` as a public input, constrain it to `< 2^160` and nonzero, and use that same public-input value as the `authVerifier` input to both `policyCommitment` and `transactionIntentDigest`. The circuit MUST NOT use a separate witnessed auth-verifier value for either computation.

The circuit MUST treat `policyOperationDataHash` as a public input, constrain it to `< p`, compute `transactOperationDataHash` as defined in Section 16.1, and enforce that `policyOperationDataHash` is either `0` or `transactOperationDataHash`. The pool profile determines which value is valid for the selected operation.

The circuit MUST treat `policyDataHash` as a public input, constrain it to `< p`, and use that same public-input value when recomputing `transactionIntentDigest`. The pool contract separately enforces that it equals `uint256(keccak256(policyData)) mod p`.

The circuit MUST treat `authorizedSubmitter` and `downstreamActionCommitment` as public inputs, constrain `authorizedSubmitter < 2^160` and `downstreamActionCommitment < p`, and absorb both into `transactIntentFieldsHash` after `publicRecipientAddress` and into `transactPublicTransitionHash` as appended trailing fields, as specified in Sections 15.6 and 16.1. The circuit does not enforce the `msg.sender == authorizedSubmitter` restriction or the `downstreamActionCommitment != 0` implies `authorizedSubmitter != 0` rule; those are contract-side checks in Section 7.1.

For each real input, the circuit MUST prove note-tree membership, recompute `ownerNullifierKeyHash`, `ownerCommitment`, `noteBodyCommitment`, `noteCommitment`, and `nullifier`, and require the recomputed note commitment to equal the opened leaf. For each phantom input, membership is skipped, `amount = 0`, and the phantom nullifier formula is used. At least one input MUST be real.

The circuit MUST use one `ownerNullifierKey` witness for all real and phantom input slots. The recomputed `ownerNullifierKeyHash` MUST equal the `ownerNullifierKeyHash` witnessed in the registry identity leaf preimage.

The circuit MUST enforce value conservation as integer arithmetic over amounts constrained to `< 2^248`:

```text
inputAmount_0 + inputAmount_1 =
    amount_0 + amount_1 + amount_2 + publicAmountOut
```

Phantom inputs and dummy outputs contribute zero.

The circuit MUST witness `noteSecretSeed` and enforce:

```text
poseidon(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed) == noteSecretSeedHash
```

where `noteSecretSeedHash` is the value witnessed in the registry identity leaf preimage. The deterministic ordinary-output `noteSecret_i` formula MUST use this `noteSecretSeed` together with `executionChainId` and `poolAddress`.

For each output slot `i`:

* `isDummy_i` MUST be constrained to `0` or `1`.
* `noteSecret_i` MUST be derived using the deterministic ordinary-output formula.
* `noteBodyCommitment_i` MUST be recomputed and equal the public input.
* If the output is real, `amount_i > 0`.
* If the output is dummy, `amount_i == 0`, `tokenAddress_i == 0`, and `ownerNullifierKeyHash_i == DUMMY_OWNER_NULLIFIER_KEY_HASH`.

The circuit MUST derive `operationKind` from the public execution mode:

* `publicAmountOut > 0` implies `operationKind == WITHDRAWAL_OP`.
* `publicAmountOut == 0` implies `operationKind == TRANSFER_OP`.

For private transfers:

* `recipientOwnerNullifierKeyHash < p`;
* `recipientOwnerNullifierKeyHash != 0`;
* `recipientOwnerNullifierKeyHash != DUMMY_OWNER_NULLIFIER_KEY_HASH`;
* slot 0 is the recipient note and MUST use `recipientOwnerNullifierKeyHash`;
* slot 0's amount MUST equal the authorization-bound `amount`;
* slot 0's token address MUST equal the authorization-bound `tokenAddress`;
* slot 1 is sender change or dummy;
* if slot 1 is real, it MUST use the sender's `ownerNullifierKeyHash`;
* slot 2 is fee note or dummy;
* `publicRecipientAddress == 0`;
* `publicTokenAddress == 0`; and
* `publicAmountOut == 0`.

For withdrawals:

* slot 0 is sender change or dummy;
* if slot 0 is real, it MUST use the sender's `ownerNullifierKeyHash`;
* slot 1 is dummy;
* slot 2 is fee note or dummy;
* `recipientOwnerNullifierKeyHash == 0`;
* `tokenAddress == publicTokenAddress`;
* `amount == publicAmountOut`;
* `publicRecipientAddress` equals the authorization-bound withdrawal recipient;
* `publicTokenAddress` equals the withdrawn token; and
* `publicAmountOut` equals the withdrawn amount.

For fee output slot 2:

* `feeAmount == 0` iff slot 2 is dummy, and then `feeNoteRecipientOwnerNullifierKeyHash == 0`.
* `feeAmount > 0` iff slot 2 is real, and then `amount_2 == feeAmount`, `feeNoteRecipientOwnerNullifierKeyHash < p`, `feeNoteRecipientOwnerNullifierKeyHash != 0`, `feeNoteRecipientOwnerNullifierKeyHash != DUMMY_OWNER_NULLIFIER_KEY_HASH`, and `ownerNullifierKeyHash_2 == feeNoteRecipientOwnerNullifierKeyHash`.

All real input and output notes MUST use the same `tokenAddress`. Amounts MUST be constrained to `< 2^248`; address-valued witnesses and public inputs MUST be constrained to `< 2^160`.

Execution constraints MUST behave as follows:

* `executionConstraintsFlags < 2^32`.
* Any flag bit other than `LOCK_OUTPUT_BINDING_0`, `LOCK_OUTPUT_BINDING_1`, or `LOCK_OUTPUT_BINDING_2` MUST cause proof failure.
* For each slot `i`, if the corresponding lock bit is set, `lockedOutputBinding_i == outputBinding_i`; otherwise `lockedOutputBinding_i == 0`.

### 9. Deployed-Pool Intent Binding

Every conforming auth relation MUST bind authorization to the intended pool identity `(chainId, poolAddress)`.

The signed or otherwise authorized intent MUST include at least:

* `chainId`,
* `poolAddress`,
* `authVerifier`,
* `authorizingAddress`,
* operation kind,
* token address,
* recipient `ownerNullifierKeyHash` for private transfers,
* amount,
* fee-note recipient `ownerNullifierKeyHash`, if any,
* fee amount, if any,
* public withdrawal recipient, if any,
* authorized submitter (`0` if any caller may submit),
* downstream action commitment (`0` if none),
* output-binding locks,
* policy data hash,
* nonce, and
* expiration.

Each auth verifier relation MUST specify how it computes:

* `authDataCommitment`,
* `blindedAuthCommitment`,
* `transactionIntentDigest`,
* any EIP-712 typed-data hash or non-EIP-712 authorization transcript, and
* the binding to `(chainId, poolAddress)`.

### 10. Registry-Backed Recipient Resolution

Registered-recipient delivery is the default path for ordinary sends to an Ethereum address. Given `(chainId, poolAddress, recipient)`, the sender obtains the recipient profile from `getPrivacyProfile(recipient)` on the canonical privacy identity registry for `chainId`.

The registered-recipient profile is usable when `registry = CANONICAL_PRIVACY_REGISTRY_ADDRESS` and:

* `extcodehash(registry) == CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH`,
* `registry.ercXXXXPrivacyRegistryId() == bytes32(keccak256("ERCXXXX_PRIVACY_IDENTITY_REGISTRY_V1"))`,
* `pool.outputNoteDataSuite() == registry.outputNoteDataSuite()`,
* `registry.outputNoteDataSuite() == "ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1"`,
* `identityRegistered == true`,
* `receiveRegistered == true`,
* `identity.ownerNullifierKeyHash < p`,
* `identity.ownerNullifierKeyHash != 0`,
* `identity.ownerNullifierKeyHash != DUMMY_OWNER_NULLIFIER_KEY_HASH`, and
* `receive.mlKem768PublicKey.length == 1184`.

An empty depth-`POLICY_SET_DEPTH` policy-set root means the recipient currently has no spendable auth method in the registry.

Registered-recipient outputs use `identity.ownerNullifierKeyHash` as the output owner hash and `receive.mlKem768PublicKey` for default encrypted delivery.

The registry identity entry remains authoritative for `ownerNullifierKeyHash`, `noteSecretSeedHash`, and `policySetCommitment` across all conforming pools on that chain. Receive-entry updates are delivery-only and do not change spend validity.

The receive entry's `metadataVersion` is recipient-controlled profile metadata for wallet cache invalidation and user-facing receive-key rotation. Registries MUST store and return the latest receive entry for `user`. Registries MUST NOT infer that a lower `metadataVersion` is stale unless the registry's own application rules define monotonic versions.

Applications MAY support out-of-band bearer or invitation flows for recipients without registry entries by using application-defined `outputNoteData` and claim procedures. Those flows are outside this ERC's default registered-recipient delivery profile.

### 11. Encrypted Output Note Data

This ERC defines the default encryption suite:

```text
ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1
```

For this suite:

* The recipient KEM public key is an ML-KEM-768 public key.
* The sender performs ML-KEM-768 encapsulation to the recipient KEM public key.
* The sender derives an AES-256-GCM key using HKDF-SHA-256 over the ML-KEM shared secret and the envelope header.
* The sender encrypts a strict-ABI note payload with AES-256-GCM.

For the default registered-recipient flow, `outputNoteData` for each real output MUST be the Solidity ABI strict encoding of this tuple:

```solidity
(
    uint256 version,
    bytes32 suiteId,
    bytes kemCiphertext,
    bytes12 nonce,
    bytes ciphertext
)
```

where `version == 1` and `suiteId == bytes32(keccak256("ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1"))`.

Implementations MUST reject non-canonical ABI offsets, overlapping dynamic tails, out-of-bounds offsets, trailing undecoded bytes, or any value whose static type does not match this tuple. The decoded `kemCiphertext` is the ML-KEM-768 ciphertext produced by ML-KEM-768 encapsulation. Decoded field lengths MUST satisfy:

* `kemCiphertext.length == 1088`.
* `ciphertext.length >= 16`, including the 128-bit AES-GCM tag.

The header bytes used by the KDF and AEAD additional authenticated data are:

```solidity
headerBytes = abi.encode(
    uint256(1),
    bytes32(keccak256("ERCXXXX_MLKEM768_HKDFSHA256_AESGCM256_ABI_V1")),
    kemCiphertext,
    nonce
)
```

The envelope layout MUST NOT be extended with a plaintext recipient key identifier, recipient address, registry pointer, registry `metadataVersion`, `ownerNullifierKeyHash`, or any other stable recipient identifier outside the ciphertext. A stable identifier derived from registry-published receive key material would let observers map on-chain output slots to recipient addresses.

The AES-GCM key MUST be derived as follows:

```text
mlKemSharedSecret = ML-KEM-768.Decapsulate/Encapsulate shared secret
ikm = mlKemSharedSecret
aadContextHash = sha256(aadContext) if aadContext is present, else empty bytes
salt = sha256(utf8("ercXXXX.private-transfer-envelope-salt-v1") || headerBytes)
info = utf8("ercXXXX.private-transfer-note-key-v1") || aadContextHash
key = HKDF-SHA-256(ikm, salt, info, 32)
```

The AES-GCM nonce MUST be the decoded `nonce` field. The AES-GCM tag length MUST be 128 bits. The AES-GCM additional authenticated data MUST be:

```text
headerBytes                                      if aadContext is absent
headerBytes || 0x00 || aadContext                otherwise
```

The default `aadContext` is absent. A non-empty `aadContext` is application-defined. `aadContext`, when present, MUST NOT contain a stable recipient identifier visible in `outputNoteData`.

Non-default out-of-band delivery formats are outside the default encrypted-delivery profile.

### 12. Note Payload

The encrypted plaintext for this ERC's default envelope MUST be the Solidity ABI strict encoding of this tuple:

```solidity
(
    uint256 version,
    uint256 kind,
    uint256 flags,
    uint256 chainId,
    address poolAddress,
    address tokenAddress,
    uint256 amount,
    uint256 ownerNullifierKeyHash,
    uint256 noteSecret,
    uint256 noteBodyCommitment,
    uint256 outputIndex,
    bytes memo
)
```

The payload constants are:

```text
NOTE_PAYLOAD_KIND_DEPOSIT = 0
NOTE_PAYLOAD_KIND_TRANSACT = 1

NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS = 1
```

Implementations MUST reject non-canonical ABI offsets, overlapping dynamic tails, out-of-bounds offsets, trailing undecoded bytes, or any value whose static type does not match this layout.

Field rules:

* `version` MUST be `1`.
* `kind` MUST be `NOTE_PAYLOAD_KIND_DEPOSIT` or `NOTE_PAYLOAD_KIND_TRANSACT`.
* `flags` is a bitset of the `NOTE_PAYLOAD_FLAG_*` constants. Any bit other than the defined flags MUST be `0`. For `kind == NOTE_PAYLOAD_KIND_TRANSACT`, `flags` MUST be `0`.
* `chainId` MUST be the execution chain ID.
* `poolAddress` MUST be the pool contract address.
* `tokenAddress` MUST be the deposited or transferred asset address, with `address(0)` representing ETH. Exception: when `NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS` is set (variable-output deposit, see below), `tokenAddress` MUST be `0` as a sentinel, not an asset claim.
* `amount` MUST be `< 2^248`. Exception: when `NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS` is set, `amount` MUST be `0` as a sentinel, not a value claim.
* `ownerNullifierKeyHash` and `noteSecret` MUST be BN254 scalar field elements in `[0, p - 1]`. `noteBodyCommitment` MUST be a BN254 scalar field element in `[0, p - 1]`, except that when `NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS` is set it MUST be `0` as a sentinel, not a commitment claim (the wallet recomputes the real commitment from the emitted event; see Section 13).
* For deposits, `outputIndex` MUST be `0`.
* For `transact`, `outputIndex` MUST be `0`, `1`, or `2`.
* `memo` is OPTIONAL opaque bytes and MUST NOT be used for note-validity checks.

The `NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS` flag selects a variable-output deposit mode for `kind == NOTE_PAYLOAD_KIND_DEPOSIT`. This mode lets a router deliver a deposit note whose final token and amount are not known when the payload is encrypted, for example a reshield deposit whose amount is the output of a public swap.

* If the flag is set, the payload `tokenAddress`, `amount`, and `noteBodyCommitment` MUST be `0`. These zeros are sentinels, not asset, value, or commitment claims: wallets MUST NOT interpret them as an ETH/zero-value/zero-commitment note, and MUST instead treat the emitted `ShieldedPoolDeposit` `tokenAddress`, `amount`, and `leafIndex` as authoritative for note reconstruction, recomputing `noteBodyCommitment` from those event-authoritative values (Section 13).
* If the flag is unset (current behavior), the payload `tokenAddress`, `amount`, and `noteBodyCommitment` MUST equal the values implied by the emitted `ShieldedPoolDeposit` event.

The payload does not include `leafIndex` or final `noteCommitment`. Emitted event values are authoritative for those fields.

This layout — including the `flags` field and the variable-output deposit mode — is the definitive `version == 1` payload for this ERC. It supersedes any earlier pre-final draft layout that also labeled itself `version == 1` but omitted `flags` or the variable-output mode; those draft layouts are not interoperable with this one and MUST NOT be produced or accepted under this ERC. The envelope suite string (`outputNoteDataSuite()`) is unchanged because the encryption suite — ML-KEM-768 + HKDF-SHA256 + AES-256-GCM over strict ABI — is unchanged; only the plaintext payload layout it carries is fixed here. Any future incompatible change to either the payload layout or the encryption suite MUST bump `version` and the suite string, respectively.

### 13. Note Discovery and Recovery

Registered-recipient outputs use the canonical privacy identity registry data from Section 10. If the recipient lacks an identity entry or receive entry, registered-recipient delivery is unavailable under this ERC.

For policy-free pools, valid submissions use `policyData = 0x`, `PublicInputs.policyOperationDataHash = 0`, and `policyDataHash = uint256(keccak256(0x)) mod p`.

The `outputNoteDataHash_i` public inputs bind the exact `outputNoteData_i` bytes submitted to `transact`. Any byte change after proof generation changes the public inputs and requires a new pool proof and authorization.

Note discovery uses `ShieldedPoolDeposit` and `ShieldedPoolTransact` events for the selected pool. Registry identity publication makes the recipient reachable in conforming pools; it does not make future or unknown pools automatically discoverable.

An accepted decrypted output is identified by:

```text
chainId || ":" || poolAddress || ":" || leafIndex || ":" || outputIndex
```

For deposits, `outputIndex` is `0`. For `transact`, output slots are `0`, `1`, and `2`.

Decryption alone is not enough to recover a spendable note. Recovery also checks chain ID, pool address, payload kind, output index, local owner hash, recomputed owner commitment, recomputed note-body commitment, and final note commitment against the emitted event commitment.

For a `kind == NOTE_PAYLOAD_KIND_DEPOSIT` payload with `NOTE_PAYLOAD_FLAG_DEPOSIT_USES_EVENT_PUBLICS` set, recovery MUST take `tokenAddress` and `amount` from the emitted `ShieldedPoolDeposit` event rather than the payload, recompute `noteBodyCommitment` from those event-authoritative values together with the local owner hash and the payload `noteSecret`, and then check the recomputed final note commitment against the emitted event commitment. When the flag is unset, recovery MUST require the payload `tokenAddress`, `amount`, and `noteBodyCommitment` to match the emitted values before acceptance.

Proof witnesses come from the event-derived note Merkle tree and the canonical privacy registry Merkle tree. Reorg-aware processing uses block/log ordering, deduplication by `(blockHash, transactionHash, logIndex)`, and enough block context to roll back note, identity, nullifier, and replay-ID state.

### 14. Transaction Submission Privacy

Direct pool submission reveals the submitting account. If a user submits `deposit` or `transact` directly from their wallet, the public chain observes that the wallet interacted with the pool.

Relayers, account abstraction, encrypted mempool submission, and other transaction infrastructure are outside this ERC. The private-transfer pool MUST NOT assume any specific transaction submission mechanism.

### 15. Detailed Cryptographic Parameters

#### 15.1 Field

All pool-circuit arithmetic is over the BN254 scalar field:

```text
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

Every public input interpreted as a field element MUST satisfy `x < p`.

#### 15.2 Fixed Constants

The following constants are fixed for this ERC:

```text
MAX_INTENT_LIFETIME = 86400
NOTE_COMMITMENT_ROOT_HISTORY_SIZE = 500
IDENTITY_ROOT_HISTORY_BLOCKS = 64
COMMITMENT_TREE_DEPTH = 32
IDENTITY_TREE_DEPTH = 32
POLICY_SET_DEPTH = 8
TRANSFER_OP = 0
WITHDRAWAL_OP = 1
POLICY_OPERATION_DEPOSIT = 0
POLICY_OPERATION_TRANSACT = 1
POLICY_APPLIES_DEPOSIT = 1 << 0
POLICY_APPLIES_TRANSFER = 1 << 1
POLICY_APPLIES_WITHDRAWAL = 1 << 2
POLICY_APPLIES_CUSTOM = 1 << 3
LOCK_OUTPUT_BINDING_0 = 1 << 0
LOCK_OUTPUT_BINDING_1 = 1 << 1
LOCK_OUTPUT_BINDING_2 = 1 << 2
CANONICAL_PRIVACY_REGISTRY_ADDRESS = TBD
CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH = TBD
CANONICAL_PRIVACY_REGISTRY_DEPLOYER = 0x4e59b44847b379578588920ca78fbf26c0b4956c
CANONICAL_PRIVACY_REGISTRY_DEPLOYMENT_SALT = TBD
CANONICAL_POOL_VERIFIER_ADDRESS = TBD
CANONICAL_POOL_VERIFIER_DEPLOYER = 0x4e59b44847b379578588920ca78fbf26c0b4956c
CANONICAL_POOL_VERIFIER_DEPLOYMENT_SALT = TBD
```

`MAX_INTENT_LIFETIME` is a maximum forward offset from `block.timestamp` to `validUntilSeconds`, not a measure of signing age.

`CANONICAL_PRIVACY_REGISTRY_ADDRESS`, `CANONICAL_PRIVACY_REGISTRY_RUNTIME_CODE_HASH`, `CANONICAL_PRIVACY_REGISTRY_DEPLOYMENT_SALT`, `CANONICAL_POOL_VERIFIER_ADDRESS`, and `CANONICAL_POOL_VERIFIER_DEPLOYMENT_SALT` MUST be fixed before this ERC is finalized. The deployment method is modeled on singleton registry ERCs: the canonical privacy identity registry and canonical pool verifier are deployed once per chain at deterministic addresses using their fixed deployers, fixed salts, and canonical initialization code.

#### 15.3 Poseidon Hash Construction

This ERC uses Poseidon2 over the BN254 scalar field with:

* state width `t = 4`
* rate `3`
* capacity `1`
* S-box `x^5`
* full rounds `R_F = 8`
* partial rounds `R_P = 56`
* external matrix, internal diagonal, and round constants exactly as specified by the Poseidon2 parameter asset published with this ERC

The single hash function used below is:

```text
poseidon(x_1, ..., x_N) = Poseidon2_sponge(x_1, ..., x_N)
```

`Poseidon2_sponge` is defined as follows. Let `N` be the number of inputs. Initialize the 4-element state to `[0, 0, 0, N << 64]`. If `N = 0`, apply one Poseidon2 permutation to this initial state and return state element `0`. Otherwise, partition the inputs into chunks of 3 elements each, zero-padding the final chunk with `0` when needed. For each chunk `[c_0, c_1, c_2]` in order, compute `state[j] = (state[j] + c_j) mod p` for `j in {0, 1, 2}`, then apply one Poseidon2 permutation to the state. After all chunks are processed, return state element `0`.

Because the capacity position encodes `N << 64`, `poseidon(a, b)` is not equivalent to the bare-permutation form that initializes capacity to `0`. Implementations MUST use the length-tagged sponge form defined here to match this ERC's hash outputs and Merkle roots.

The corresponding Poseidon2 vector asset published with this ERC provides test vectors for this construction.

#### 15.4 Merkle Tree Constructions

All Merkle trees in this ERC hash internal nodes as `poseidon(left, right)` using the length-tagged sponge in Section 15.3. Implementations MUST NOT use a bare Poseidon2 permutation or a Merkle-node hash with a different initial state.

For every Merkle tree in this ERC, empty leaves are `0` and empty internal nodes follow this ladder:

```text
EMPTY[0] = 0
EMPTY[h + 1] = poseidon(EMPTY[h], EMPTY[h])
```

The empty root of a depth-`D` tree is `EMPTY[D]`.

A Merkle membership proof for a depth-`D` tree is an ordered list of `D` sibling nodes from leaf level upward. At height `h` in `[0, D - 1]`, bit `h` of the tree key is interpreted least-significant-bit first. If the bit is `0`, the current node is the left child and the sibling is the right child. If the bit is `1`, the sibling is the left child and the current node is the right child. The next node is `poseidon(left, right)`.

The note commitment tree is a depth-32 append-only tree. Its key is `leafIndex`. Leaf indices are `uint32` values in `[0, 2^32 - 1]`, assigned sequentially from `0`. A `deposit` appends one nonzero final note commitment at `nextLeafIndex`; a `transact` appends three nonzero final note commitments at `nextLeafIndex`, `nextLeafIndex + 1`, and `nextLeafIndex + 2`, in that order. Appending a leaf writes the value at its LSB-first path, recomputes all ancestors using existing sibling subtree roots, uses the empty ladder only for subtrees that have never been written, and increments `nextLeafIndex` by the number of inserted leaves.

The privacy identity registry tree is a depth-32 sparse mutable tree keyed by `leafPosition`, interpreted LSB-first. `leafPosition` values are `uint32` values. Position `0` is the unassigned sentinel and MUST NOT be assigned to a registered address. Empty leaves are `0`. A registered identity leaf is:

```text
poseidon(IDENTITY_LEAF_DOMAIN, uint160(user), ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment)
```

The policy-set tree is a depth-`POLICY_SET_DEPTH` sparse tree of `policyCommitment` leaves, keyed LSB-first by wallet-selected slot positions. It is computed off-chain by the wallet and is not maintained by the pool. Empty slots are `0`. The empty policy-set root is `EMPTY[POLICY_SET_DEPTH]` under this same construction.

#### 15.5 Domain Tags

Each domain tag is:

```text
DOMAIN = uint256(keccak256("erc-app-layer-private-transfers." || context_name)) mod p
```

This ERC defines those literal domain strings here for this ERC's private-transfer relation; it does not rely on another EIP as a normative source.

| Constant | Context string |
|----------|----------------|
| `OWNER_NULLIFIER_KEY_HASH_DOMAIN` | `owner_nullifier_key_hash` |
| `OWNER_COMMITMENT_DOMAIN` | `owner_commitment` |
| `NOTE_BODY_COMMITMENT_DOMAIN` | `note_body_commitment` |
| `NOTE_COMMITMENT_DOMAIN` | `note_commitment` |
| `NULLIFIER_DOMAIN` | `nullifier` |
| `PHANTOM_NULLIFIER_DOMAIN` | `phantom_nullifier` |
| `INTENT_REPLAY_ID_DOMAIN` | `intent_replay_id` |
| `TRANSACT_NOTE_SECRET_DOMAIN` | `transact_note_secret` |
| `NOTE_SECRET_SEED_DOMAIN` | `note_secret_seed` |
| `TRANSACT_INTENT_FIELDS_DOMAIN` | `transact_intent_fields` |
| `TRANSACTION_INTENT_DIGEST_DOMAIN` | `transaction_intent_digest` |
| `OUTPUT_BINDING_DOMAIN` | `output_binding` |
| `IDENTITY_LEAF_DOMAIN` | `identity_leaf` |
| `POLICY_COMMITMENT_DOMAIN` | `policy_commitment` |
| `POLICY_OPERATION_DOMAIN` | `policy_operation` |
| `POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN` | `policy_transact_public_transition` |
| `POLICY_TRANSACT_OPERATION_DATA_DOMAIN` | `policy_transact_operation_data` |
| `POLICY_DEPOSIT_OPERATION_DATA_DOMAIN` | `policy_deposit_operation_data` |
| `BLINDED_AUTH_COMMITMENT_DOMAIN` | `blinded_auth_commitment` |

#### 15.6 Derived Values

The dummy owner hash is:

```text
DUMMY_OWNER_NULLIFIER_KEY_HASH =
    poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, 0xdead)
```

Owner hashes, owner commitments, note commitments, and nullifiers are:

```text
ownerNullifierKeyHash =
    poseidon(OWNER_NULLIFIER_KEY_HASH_DOMAIN, ownerNullifierKey)

ownerCommitment =
    poseidon(OWNER_COMMITMENT_DOMAIN, executionChainId, poolAddress, ownerNullifierKeyHash, noteSecret)

noteBodyCommitment =
    poseidon(NOTE_BODY_COMMITMENT_DOMAIN, ownerCommitment, amount, tokenAddress)

noteCommitment =
    poseidon(NOTE_COMMITMENT_DOMAIN, executionChainId, poolAddress, noteBodyCommitment, leafIndex)

nullifier =
    poseidon(NULLIFIER_DOMAIN, executionChainId, poolAddress, noteCommitment, ownerNullifierKey)

phantomNullifier =
    poseidon(PHANTOM_NULLIFIER_DOMAIN, executionChainId, poolAddress, ownerNullifierKey, intentReplayId, inputIndex)
```

Registry identity and auth-method values are:

```text
noteSecretSeedHash =
    poseidon(NOTE_SECRET_SEED_DOMAIN, noteSecretSeed)

policyCommitment =
    poseidon(POLICY_COMMITMENT_DOMAIN, uint160(authVerifier), authDataCommitment, registrationBlinder)

identityLeaf =
    poseidon(IDENTITY_LEAF_DOMAIN, uint160(user), ownerNullifierKeyHash, noteSecretSeedHash, policySetCommitment)

blindedAuthCommitment =
    poseidon(BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor)
```

For ordinary `transact` outputs, the note secret is deterministic:

```text
noteSecret_i =
    poseidon(TRANSACT_NOTE_SECRET_DOMAIN, noteSecretSeed, executionChainId, poolAddress, intentReplayId, i)
```

For deposits, the depositor chooses `noteSecret` and delivers it to the recipient through `outputNoteData` or out-of-band coordination.

The intent replay ID is:

```text
intentReplayId =
    poseidon(INTENT_REPLAY_ID_DOMAIN, ownerNullifierKey, authorizingAddress, executionChainId, poolAddress, nonce)
```

The policy data hash is:

```text
policyDataHash =
    uint256(keccak256(policyData)) mod p
```

For policy-free pools, `policyData` is `0x`, `policyDataHash` is `uint256(keccak256(0x)) mod p`, and `policyOperationDataHash` is `0`. Optional policy-gated profiles define the additional policy operation hashes in Section 16.1.

The transact intent fields hash is:

```text
transactIntentFieldsHash = poseidon(
    TRANSACT_INTENT_FIELDS_DOMAIN,
    poolAddress,
    authVerifier,
    authorizingAddress,
    operationKind,
    tokenAddress,
    recipientOwnerNullifierKeyHash,
    amount,
    feeNoteRecipientOwnerNullifierKeyHash,
    feeAmount,
    publicRecipientAddress,
    authorizedSubmitter,
    downstreamActionCommitment,
    executionConstraintsFlags,
    lockedOutputBinding0,
    lockedOutputBinding1,
    lockedOutputBinding2,
    nonce,
    validUntilSeconds,
    executionChainId
)
```

The transaction intent digest is:

```text
transactionIntentDigest = poseidon(
    TRANSACTION_INTENT_DIGEST_DOMAIN,
    transactIntentFieldsHash,
    policyDataHash
)
```

The output note data hash and output binding are:

```text
outputNoteDataHash_i =
    uint256(keccak256(outputNoteData_i)) mod p

outputBinding_i =
    poseidon(OUTPUT_BINDING_DOMAIN, noteBodyCommitment_i, outputNoteDataHash_i)
```

### 16. Optional Policy Profile

The base private-transfer profile is policy-free. Policy-free pools are conforming pools and use the empty policy-data convention in Sections 15.6, 7, 8, and 16.1.

Pool-level policy checks are optional at the pool-profile level. They are not user auth policies. If a pool profile requires policy for an operation, the operation succeeds only when the pool-selected `policyVerifier()` accepts the operation.

#### 16.1 Policy Verification

Policy verifiers MUST implement:

```solidity
interface IERCXXXXPolicyVerifier {
    function verifyPolicy(
        bytes calldata publicInputs,
        bytes calldata policyData
    ) external view returns (bool);
}
```

If `policyAppliesToOperations() == 0`, `policyVerifier()` MUST return `address(0)`. If `policyAppliesToOperations() != 0`, `policyVerifier()` MUST be nonzero.

`policyData` is opaque to the pool. A policy verifier MAY parse `policyData` as a bundle and compose any verifier, proof, credential, list, disclosure, or state-root checks required by that policy profile.

The generic policy operation digest is:

```text
policyVerifierField =
    uint160(policyVerifier())

policyOperationDigest =
    poseidon(
        POLICY_OPERATION_DOMAIN,
        chainId,
        poolAddress,
        policyVerifierField,
        policyOperationKind,
        operationDataHash
    )
```

`operationDataHash` is the hash of operation-specific public data. It MUST NOT depend on `policyData`.

For standard `transact`, `transactIntentFieldsHash` is the value defined in Section 15.6. The additional policy operation-data hashes are:

```text
transactPublicTransitionHash = poseidon(
    POLICY_TRANSACT_PUBLIC_TRANSITION_DOMAIN,
    noteCommitmentRoot,
    nullifier0,
    nullifier1,
    noteBodyCommitment0,
    noteBodyCommitment1,
    noteBodyCommitment2,
    publicAmountOut,
    publicRecipientAddress,
    publicTokenAddress,
    intentReplayId,
    validUntilSeconds,
    executionChainId,
    poolAddress,
    identityRoot,
    outputNoteDataHash0,
    outputNoteDataHash1,
    outputNoteDataHash2,
    authVerifier,
    blindedAuthCommitment,
    authorizedSubmitter,
    downstreamActionCommitment
)

transactOperationDataHash = poseidon(
    POLICY_TRANSACT_OPERATION_DATA_DOMAIN,
    transactIntentFieldsHash,
    transactPublicTransitionHash
)
```

For standard `transact`, the pool profile MUST determine policy applicability using `POLICY_APPLIES_TRANSFER` when `publicAmountOut == 0` and `POLICY_APPLIES_WITHDRAWAL` when `publicAmountOut > 0`. Both cases use `POLICY_OPERATION_TRANSACT`; the underlying `transactOperationDataHash` includes the circuit-derived `operationKind`.

For an ungated `transact` operation, the pool MUST require `publicInputs.policyOperationDataHash == 0` and `policyData.length == 0`. For a policy-gated `transact` operation, the pool MUST require `publicInputs.policyOperationDataHash != 0`, treat it as the circuit-authenticated `operationDataHash`, compute `policyOperationDigest` with `policyOperationKind = POLICY_OPERATION_TRANSACT`, and dispatch to `policyVerifier()`.

For standard `transact`, `operationDataHash` is `transactOperationDataHash`, not `transactionIntentDigest`. `transactionIntentDigest` includes `policyDataHash` so authorization can bind the finished policy bytes; `transactOperationDataHash` excludes `policyDataHash` so policy data can be produced before final encoding. It reuses the same `transactIntentFieldsHash` as `transactionIntentDigest` and also binds the public transition, so policy data cannot be reused for a different set of public inputs with the same intent fields.

For standard `deposit`, the pool MUST compute:

```text
depositOperationDataHash = poseidon(
    POLICY_DEPOSIT_OPERATION_DATA_DOMAIN,
    block.chainid,
    uint160(address(this)),
    uint160(msg.sender),
    uint160(token),
    amount,
    ownerCommitment,
    outputNoteDataHash
)

policyOperationDigest =
    poseidon(
        POLICY_OPERATION_DOMAIN,
        block.chainid,
        uint160(address(this)),
        uint160(policyVerifier()),
        POLICY_OPERATION_DEPOSIT,
        depositOperationDataHash
    )
```

If `POLICY_APPLIES_DEPOSIT` is not set, `deposit` MUST require `policyData.length == 0`. If `POLICY_APPLIES_DEPOSIT` is set, `deposit` MUST compute `policyOperationDigest` with `policyOperationKind = POLICY_OPERATION_DEPOSIT` and dispatch to `policyVerifier()`.

When dispatching to `policyVerifier()`, the pool MUST call `verifyPolicy` using `staticcall`, pass `publicInputs = abi.encode(policyOperationDigest)`, pass `policyData = policyData`, and treat revert, malformed returndata, or decoded `false` as policy failure.

For policy-gated standard `transact`, a valid submission contains policy data for `transactOperationDataHash`, sets `PublicInputs.policyOperationDataHash` to that value, computes `policyDataHash` from the exact `policyData` bytes, and includes that data hash in `PublicInputs` and in the signed or otherwise authorized intent.

Proof-carrying policy data can become part of note recoverability for policy-gated pool profiles.

Custom pool-profile functions can require `policyData` parameters. Such functions are outside the base pool ABI, but if they claim ERC-compatible policy handling, they MUST compute a `policyOperationDigest` using `POLICY_OPERATION_DOMAIN`, `policyVerifier()`, a profile-defined `policyOperationKind`, and an operation-data hash that commits to the function-specific public data. The operation-data hash MUST NOT depend on `policyData`. Custom `policyOperationKind` values MUST be `< p` and MUST NOT equal `POLICY_OPERATION_DEPOSIT` or `POLICY_OPERATION_TRANSACT`.

Common pool-profile extensions include pending-deposit activation, pending-deposit refund, policy-independent public exit, and policy-gated withdrawal disclosure. Those entry points are outside the base ABI. If a custom entry point uses ERC-compatible policy handling, it MUST accept `policyData`, compute a profile-defined operation-data hash over all public operation parameters and relevant state identifiers, compute `policyOperationDigest`, and dispatch to `policyVerifier()` as defined in this section. If a custom entry point is policy-exempt by design, it MUST require no policy data for that entry point.

### 17. Optional Public Action / Reshield Router Profile

This section describes an OPTIONAL router-mediated public action built from base-pool primitives. It is outside the base pool ABI. The base pool exposes no router entry point; a router is a separate contract that composes a private withdrawal, one or more public calls, and one or more reshield deposits.

A router-mediated public action is a private withdrawal from a source pool, followed by public calls the router performs with the withdrawn assets, followed by reshield `deposit`s of the resulting assets back into a pool. The canonical example is an unshield-to-adapter-then-reshield router: the source `transact` withdraws to the router, the router runs a public action such as a swap through an adapter, and the router reshields the output using a variable-output deposit (Section 12).

To bind the withdrawal to the router and its action plan, the source `transact` intent MUST set:

* `authorizedSubmitter = uint160(router)`, so only the router may submit the withdrawal (Section 7.1); and
* `downstreamActionCommitment = actionPlanCommitment`, an opaque commitment to the router's action spec.

Because `publicAmountOut > 0`, the withdrawal moves the public asset to `publicRecipientAddress`. For this profile, `publicRecipientAddress` MUST be the router. Before calling `transact`, the router MUST verify that `publicRecipientAddress == uint160(router)` and that the supplied action spec hashes to `downstreamActionCommitment`. The commitment scheme for the action spec is router-defined and outside this ERC.

The `downstreamActionCommitment` MUST cover every value-affecting and recipient-affecting parameter of the plan, so that committing to it fully determines where value can go. At minimum this includes: the ordered set of downstream calls and their targets; a hash of each call's calldata; per-leg minimum outputs; deadlines; each target reshield pool; each reshield `ownerCommitment` and `outputNoteData` hash; reshield policy data; and any refund address, dust destination, or fee recipient the router uses. A parameter left out of the commitment is a parameter the user did not authorize, and the router MUST NOT let it influence value routing.

The router MUST be safe under third-party submission. Because the withdrawal proof and the full router calldata are public once broadcast, any address may relay the exact same `executeMove` calldata. The router MUST execute the same committed plan regardless of who submits it, and MUST NOT derive any recipient, refund, dust destination, or fee target from `msg.sender` or from any calldata field that is not bound by `downstreamActionCommitment`. Realized outputs and any residual value MUST flow only to destinations fixed by the commitment (for example the committed reshield `ownerCommitment`), never to the submitter.

The safety property is a two-level trust boundary:

* The pool guarantees only that the named `authorizedSubmitter` (the router) can execute the withdrawal leg. The pool does not interpret `downstreamActionCommitment` and does not vouch for router correctness.
* The router guarantees that it executes only the action spec that matches `downstreamActionCommitment`, that it does so only when `publicRecipientAddress` is the router, and that the realized plan is independent of who submits the transaction.

The pool does not vouch for router correctness. The trust boundary is the user's choice of router: the user's authorization names a specific router and commits to a specific action plan, but a buggy or malicious router that a user names can still misuse the withdrawn public assets within the scope of that withdrawal. Base-pool invariants such as value conservation, note membership, nullifier checks, and token consistency continue to hold for the private legs regardless of router behavior.

## Rationale

### Relationship to EIP-8182

This ERC and EIP-8182 share the same note, nullifier, and split-authorization core but answer the pool-fragmentation problem differently. EIP-8182 resolves it by enshrinement: one protocol pool, hard-fork governance, no competition. This ERC takes the opposite bet: a single pool frozen behind hard-fork governance forecloses innovation in policy, governance, asset curation, and deployment trust models. This ERC standardizes the interoperability surface so pools can compete without fragmenting the engineering, and leaves liquidity consolidation to the market. The two can coexist; their domain-tag namespaces are disjoint, so artifacts never collide.

### Pool Fragmentation

Fragmented deployment weakens anonymity, and this ERC accepts that risk deliberately. Three properties push toward consolidation. Registry identity is pool-independent: a recipient registers once and is reachable on every conforming pool, so joining a new pool has near-zero onboarding cost. Atomic unshield-and-reshield moves value between pools in one transaction, so anonymity sets are not sticky and users can migrate to the largest or best-governed pool. Shared circuit, wallet, prover, and indexer infrastructure means pools compete on pool-level properties rather than tooling. This is still a bet: a chain with many small pools gets weaker privacy than one enshrined pool. The standard lowers the cost of consolidation; it cannot force it.

### Deployed Pools

Teams can deploy private-transfer pools as ordinary Ethereum contracts. This ERC makes pool identity, registry-backed authorization, privacy identity discovery, and note delivery explicit so wallets, provers, indexers, and applications can interoperate across independently deployed pools.

### Deployment Governance

Deployment controls are part of the deployment's trust assumptions. The base interface deliberately excludes admin, pause, and upgrade functions so that governance is a per-deployment property users and wallets evaluate, not something the standard prescribes. An immutable policy-free pool and a governed compliance pool are both conforming, and they compete.

### One Canonical Circuit and Verifier

Wallets, provers, and auditors target exactly one relation. Per-pool circuits would recreate the fragmentation this ERC exists to remove and would multiply trusted setups. Pools differentiate on everything around the relation — policy, governance, assets — not on the relation itself. A relation change is a successor version of this ERC with a new canonical verifier; each pool chooses its own posture toward successors: stay immutable, or migrate under its own governance.

### Immutable Canonical Singletons

The canonical registry and pool verifier are validity-critical shared state for every conforming pool. Admin authority over them would be admin authority over every pool at once, so both are immutable. The escape hatch is versioning, not administration: a successor ERC deploys successor singletons. Because the receive plane is delivery-only, migrating the encryption suite in a successor version costs one re-registration transaction per user and invalidates no notes and no funds.

### Pool Identity

For deployed contracts, `(chainId, poolAddress)` is the pool identity. Payloads, wallet state, and auth relations bind directly to that pair.

### Pool Introspection

The pool proof verifier, proof ABI, and public-input order are fixed by this ERC. The pool introspection functions provide pool-specific metadata for the Poseidon parameter asset, default note-delivery suite, and policy-profile discovery. Recipient identity and receive data come from the canonical privacy identity registry for the chain.

### Privacy Identity Registry

Senders need both encryption material and the recipient's owner hash. The canonical privacy identity registry therefore publishes one address-bound identity/auth entry plus one receive entry for all conforming pools on the chain. This avoids per-pool setup while preserving separate note trees, nullifier sets, liquidity, and anonymity sets for each pool. Separate Ethereum addresses provide separate privacy contexts.

The registry is specialized rather than a generic metadata or interface registry because identity leaves, root histories, owner-hash uniqueness, and policy-set commitments are part of the pool validity relation.

The identity leaf excludes the receive entry because receive-key rotation does not affect spend validity. The ML-KEM public key is also too large to include in the validity-critical ZK leaf without a specific need.

### Pool-Scoped Derived Values

Registry identity material is chain-global. Note commitments, owner commitments, nullifiers, phantom nullifiers, replay IDs, and deterministic transact note secrets are pool-local derived values. Including `(executionChainId, poolAddress)` in those formulas prevents shared registry identity material from creating identical or linkable artifacts across pools.

### Opinionated Encryption

The pool treats `outputNoteData` as bytes. The default suite is ML-KEM-only: recipients publish one post-quantum receive record, and senders produce trial-decryptable note payloads using that record. ML-KEM-768 is FIPS 203-standardized, and a hybrid suite would add per-output calldata and implementation surface. The blast radius of a KEM failure is bounded: it degrades delivery privacy and note recoverability, never fund security, because funds bind to note commitments rather than envelopes. Future ERCs or application profiles can define additional suites, including post-quantum/traditional hybrids.

### Post-Quantum Scope

This ERC's post-quantum posture is limited. The default encrypted note-delivery suite is intended to resist harvest-now-decrypt-later attacks against `outputNoteData`. The pool proof system is Groth16 over BN254, and auth profiles may rely on non-post-quantum proof systems or signature schemes. Long-lived deployments need a migration path before practical quantum attacks against those assumptions are available.

### No Plaintext Key Identifier

The encrypted envelope omits a plaintext key identifier. A stable `kid` derived from registry-published receive key material would let observers precompute address-to-key mappings from the public registry and match those identifiers against on-chain `outputNoteData`. Recipients instead trial-decrypt pool events with their local ML-KEM receive keys.

### Opaque Pool Validation

The pool validates only hashes of `outputNoteData` because note delivery is a wallet concern. Parsing envelopes in the pool would add cost, freeze one delivery format into pool execution, and make future delivery changes harder.

### Optional Policy Verifiers

Compliance, credential, membership, disclosure, and clean-history requirements vary by deployment. This ERC therefore standardizes a policy data interface and binding rule rather than one compliance regime. A pool profile decides whether policy applies to deposits, private transfers, withdrawals, public exits, pending-deposit activation, or custom functions.

The generic `policyOperationDigest` lets the same policy verifier be reused across different pool functions and pool profiles. For example, one pool can use a verifier as a hard deposit gate, while another can use the same verifier during pending-deposit activation before a note enters the private set.

For standard `transact`, policy checks bind to `transactOperationDataHash` rather than `transactionIntentDigest`; the circuit permits either `0` or that hash so the same pool relation works for policy-free and policy-gated pools.

Pending-deposit quarantine, public refund, unconditional public exit, and proof-carrying clean-history notes are pool-profile designs outside the base ABI. Those profiles can reuse `policyData`, `policyOperationDigest`, and `IERCXXXXPolicyVerifier` instead of defining a different policy architecture for each function.

## Backwards Compatibility

This ERC is not backwards compatible with arbitrary existing privacy pools. It is compatible with pools that use the canonical privacy identity registry, verify pool proofs with the canonical pool verifier, and implement this ERC's pool semantics, pool introspection, auth-binding requirements, event surface, registered-recipient discovery, envelope requirements, and any optional profiles they claim to support.

Existing deployments that use the same pool interface but do not bind authorization to `(chainId, poolAddress)` can add pool-specific auth verifiers or migrate users to a conforming deployment.

## Security Considerations

Each deployed pool has its own liquidity and user set, so fragmented deployment weakens anonymity.

Pool, registry, auth-verifier, and policy-verifier governance are deployment trust assumptions. Pool-level upgrade, pause, freeze, or custody authority can affect all users of that pool. Canonical registry governance can affect every conforming pool on that chain. The canonical pool verifier is immutable; it carries the same proof-system and implementation correctness assumptions as an equivalent verifier embedded directly in each pool. Auth-verifier governance affects identities that register that verifier. Policy-verifier governance affects operations gated by that policy profile.

Privacy identity registry publication links an Ethereum address to a chain-wide private-transfer identity, receive metadata, and `ownerNullifierKeyHash`. The registry does not hide who can receive encrypted notes, but it also does not reveal which pool a user intends to use.

Publishing or distributing an `ownerNullifierKeyHash` before registering the corresponding registry identity can let another address claim that owner hash in the canonical registry. Registered-recipient delivery depends on the current registry identity entry and receive entry.

A weak auth method in a registry identity can authorize spends across every conforming pool on the chain. Distinct Ethereum addresses provide distinct auth surfaces.

A user who includes an auth verifier in their registry-level policy set trusts that verifier across every conforming pool on the chain. A malicious or buggy auth verifier can authorize spends for that identity in any pool accepting an identity root that includes the policy. It cannot bypass pool-level invariants such as value conservation, note membership, nullifier checks, token consistency, or output constraints, but it can compromise the user's notes where that verifier is an accepted authorization path.

Each `ShieldedPoolTransact` event reveals the public `authVerifier` used for that spend. The registry does not publish which identities have registered which policies, but once a spend occurs, observers learn the auth method used for that transaction. Widely used auth profiles provide a larger apparent sender set.

Pool-level policy verifiers are pool-wide rules, not user-selected auth methods. A policy verifier generally cannot drain funds by itself because the pool proof and auth proof still enforce note ownership, nullifiers, value conservation, token consistency, and output constraints. It can censor deposits, transfers, withdrawals, or exits if the pool profile applies policy to those operations.

Mutable pool-level policy can change whether policy-gated operations are accepted and can affect pool selection and recoverability.

Policy data bytes are public transaction data. Stable account identifiers, credential identifiers, recipient identifiers, or unnecessary disclosure data in `policyData` can link users or operations.

Proof-carrying policy data can become part of note recoverability for policy-gated pool profiles. Losing that data can make a note unspendable under that profile even when the owner still has the note secret and owner key.

Stable recipient identifiers in `outputNoteData` can deanonymize recipients. Envelopes MUST NOT include plaintext key IDs, recipient addresses, registry pointers, metadata versions, owner hashes, or other stable recipient hints. A wallet that emits such identifiers can make output slots linkable to registry entries.

A malicious sender can emit undecryptable or malformed `outputNoteData`. This cannot redirect funds if the note commitment is valid, but it can prevent the recipient from recovering the note. Unlocked output bindings permit authorization over outputs whose delivery bytes are finalized later.

Variable-size `outputNoteData` can reveal which output slots are real, change, fee, or dummy. Common size classes reduce that leakage.

Low-entropy nonce, blinding, note-secret, or encryption randomness can deanonymize users or make notes linkable. Cryptographic randomness is needed for randomness not deterministically derived by the pool relation.

`ownerNullifierKey` and `noteSecretSeed` can be derived from wallet-controlled secret material, including deterministic signing flows. Such derivation is wallet-side only. Recoverability matters because `ownerNullifierKeyHash` is non-rotatable and `noteSecretSeedHash` rotation only affects future deterministic output secrets.

Deriving `ownerNullifierKey` or `noteSecretSeed` from ordinary transaction authorization signatures can expose durable note-control material to routine signing flows. Signing-based derivation uses a fixed derivation message, domain-separated from spend intents and bound to `(chainId, account)`.

Cross-pool replay is a deployment-specific risk. Auth relations MUST bind authorization to `(chainId, poolAddress)`.

Withdrawal authorization is bearer authorization unless a submitter is named. A withdrawal intent authorizes moving a public asset amount to `publicRecipientAddress`, and its pool and auth proofs are self-contained. Once those proofs are visible, for example in the public mempool, any observer can submit the withdrawal leg by itself. When the withdrawal is meant to be one step of a larger router action, a third party can execute just the withdrawal and skip the intended downstream step, stranding funds at `publicRecipientAddress`. This griefing vector is most severe for ERC-20 assets, which have no receiver hook that could re-attach the withdrawal to a follow-on action. Setting `authorizedSubmitter` to a nonzero address closes this vector by making the authorization named rather than bearer: only that address may submit the withdrawal, and `downstreamActionCommitment` lets the authorization additionally bind the submitter's committed downstream action. `authorizedSubmitter == 0` preserves the permissionless-submission behavior for intents where any submitter is acceptable.

Auth profiles that expose signatures, signing public keys, or authorizing addresses in calldata can reveal the sender. Privacy-preserving auth profiles keep those values as private proof witnesses.

This ERC is not post-quantum secure as a whole. ML-KEM-768 note delivery is intended to protect already-published encrypted note payloads from later decryption, but Groth16 BN254 pool proof soundness and many practical auth profiles are not quantum-resistant. Long-lived deployments need a migration path before those assumptions fail.

## Test Cases

Useful test coverage includes:

* pool, registry, auth-verifier, and policy-verifier governance assumptions;
* Merkle tree construction, append semantics, root histories, and tree-capacity boundaries;
* identity registration, owner-hash uniqueness, reserved-value rejection, policy-set roots, and receive-entry updates;
* pool proof public-input validation, circuit relation constraints, note/nullifier derivation, value conservation, output bindings, dummy slots, and fee-output binding;
* `deposit`, private-transfer, withdrawal, ETH, ERC-20, and incompatible-token execution paths;
* auth-verifier dispatch, intent binding, replay rejection, and cleartext privacy rejection;
* policy-free empty-policy-data behavior and, for policy-gated profiles, operation-digest binding, policy-verifier dispatch, and custom operation kinds;
* registered-recipient discovery, registry suite matching, strict-ABI note-envelope decoding, payload validation, and trial decryption.

## Appendix A: Informational EIP-712 Auth Sketch

This appendix is non-normative. It sketches one practical auth profile for wallets that want ordinary Ethereum EIP-712 signing at the user interface while keeping the signature, signing public key, and authorizing address private from pool calldata. The base ERC treats this as one auth method among many.

In this design, the auth verifier implements `IERCXXXXAuthVerifier.verifyAuth(bytes publicInputs, bytes proof)`, where:

```text
publicInputs = abi.encode(
    uint256 blindedAuthCommitment,
    uint256 transactionIntentDigest
)
```

The proof system can be UltraHonk over BN254. A verifier generated with Barretenberg `bb prove --scheme ultra_honk -t evm` and `bb write_solidity_verifier --scheme ultra_honk -t evm` is a natural construction.

The wallet registers a policy commitment whose `authVerifier` is the selected verifier address and whose auth data binds the registered Ethereum address:

```text
EIP712_AUTH_DATA_DOMAIN = uint256(keccak256("erc-app-layer-private-transfers.eip712_auth_data")) mod p

authDataCommitment =
    poseidon(EIP712_AUTH_DATA_DOMAIN, uint160(authorizingAddress))
```

The EIP-712 domain can be:

```text
EIP712Domain(
    string name,
    string version,
    uint256 chainId,
    address verifyingContract
)
```

with `name = "ERCXXXXPrivateTransfers"`, `version = "1"`, `chainId = executionChainId`, and `verifyingContract = poolAddress`.

The primary type can be:

```text
PrivateTransferIntent(uint256 chainId,address poolAddress,address authVerifier,address authorizingAddress,uint256 operationKind,address tokenAddress,uint256 recipientOwnerNullifierKeyHash,uint256 amount,uint256 feeNoteRecipientOwnerNullifierKeyHash,uint256 feeAmount,address publicRecipientAddress,address authorizedSubmitter,uint256 downstreamActionCommitment,uint256 executionConstraintsFlags,uint256 lockedOutputBinding0,uint256 lockedOutputBinding1,uint256 lockedOutputBinding2,uint256 policyDataHash,uint256 nonce,uint256 validUntilSeconds)
```

The typed-data fields match the same values used to compute `transactIntentFieldsHash` and `transactionIntentDigest` in Section 15.6. The `authVerifier` field is the verifier address that the pool dispatches to, and the policy commitment uses that same verifier address.

The auth proof relation would:

1. Compute the EIP-712 digest for the domain and `PrivateTransferIntent`.
2. Verify a low-s secp256k1 ECDSA signature over that digest.
3. Recover or verify the signing public key and require the corresponding Ethereum address to equal `authorizingAddress`.
4. Check that typed-data `chainId` and `poolAddress` match the pool identity used in `transactionIntentDigest`.
5. Use typed-data `authVerifier` as the verifier value used to recompute `transactionIntentDigest`.
6. Recompute `authDataCommitment` and `blindedAuthCommitment`.
7. Recompute `transactIntentFieldsHash` and `transactionIntentDigest`.
8. Return success only when the recomputed `blindedAuthCommitment` and `transactionIntentDigest` equal the two public inputs supplied by the pool.

A nonce with at least 128 bits of entropy avoids accidental reuse. The pool's consumed `intentReplayId` prevents successful replay after inclusion, but duplicate signatures for the same `(authorizingAddress, executionChainId, poolAddress, nonce)` create unnecessary recoverable intent material.

This profile binds the verifier address through `transactionIntentDigest`: the typed-data `authVerifier` field is included in the digest, the pool circuit recomputes that digest using the public `authVerifier` input, and the pool contract dispatches `authProof` to that same public `authVerifier` address.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
