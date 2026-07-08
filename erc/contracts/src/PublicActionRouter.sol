// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IShieldedPool} from "./interfaces/IShieldedPool.sol";
import {ERC20AssetLib} from "./libraries/ERC20AssetLib.sol";

/// @title  Public-action / reshield router (spec section 17, optional profile)
/// @notice Singleton router that atomically unshields value from a source pool,
///         optionally routes it through one external action (swap / bridge
///         slot), then reshields the realized output into a target pool.
///
/// @dev    Theft safety. The router relies on the two transact public inputs
///         added in spec section 7.1:
///           * `authorizedSubmitter == address(this)` — the source pool only
///             lets THIS router trigger the withdrawal, so a mempool observer
///             cannot replay the proof against the pool directly.
///           * `downstreamActionCommitment == computeDownstreamActionCommitment(
///             ...)` — the exact reshield/action spec is bound into the pool
///             proof. A caller who varies any spec field yields a different
///             commitment and the pool proof no longer authenticates it, so the
///             move reverts before consuming the user's nullifiers.
///
///         For a plain pool-to-pool move, callers set `actionTarget == 0`,
///         `actionCalldata == ""`, and `tokenIn == tokenOut`. Stateless aside
///         from a transient in-run flag gating `receive()`; no admin, no
///         upgrade path.
contract PublicActionRouter {
    /// @notice The unshield (from.transact) leg.
    struct MoveIn {
        IShieldedPool from;
        bytes poolProof;
        bytes authProof;
        IShieldedPool.PublicInputs publicInputs;
        bytes outputNoteData0;
        bytes outputNoteData1;
        bytes outputNoteData2;
        bytes policyData;
    }

    /// @notice The downstream action + reshield spec. Its hash is bound into the
    ///         pool proof via `downstreamActionCommitment`.
    struct ActionSpec {
        address sourcePool;
        address tokenIn;
        uint256 amountIn;
        address targetPool;
        address tokenOut;
        uint256 ownerCommitment;
        bytes depositNoteData;
        bytes depositPolicyData;
        uint256 minOut;
        uint256 routerDeadline;
        // For the reference profile: a same-asset move (no swap) when
        // actionTarget == 0, or a single external call (swap / bridge) otherwise.
        address actionTarget;
        bytes actionCalldata;
    }

    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Set to 1 only while executeMove() is running; gates receive().
    bytes32 private constant RUN_GUARD_SLOT = keccak256("PublicActionRouter.run.guard");

    error SubmitterNotRouter();
    error RecipientNotRouter();
    error CommitmentMismatch();
    error AmountMismatch();
    error TokenMismatch();
    error SourcePoolMismatch();
    error RouterDeadlinePassed();
    error ActionCallFailed();
    error InsufficientOutput();
    error EthNotDuringRun();
    error ApprovalFailed();
    error ReentrantCall();
    error ResidualInput();
    error ResidualOutput();

    /// @notice The field-reduced commitment binding a withdrawal to an exact
    ///         downstream action + reshield spec. Off-chain callers and the
    ///         circuit compute the same value for `downstreamActionCommitment`.
    function computeDownstreamActionCommitment(
        uint256 executionChainId,
        address sourcePool,
        uint256 intentReplayId,
        ActionSpec calldata spec
    ) public view returns (uint256) {
        bytes32 actionHash = keccak256(abi.encode(spec.actionTarget, spec.actionCalldata));
        bytes32 reshieldHash = keccak256(
            abi.encode(
                spec.targetPool,
                spec.tokenOut,
                spec.ownerCommitment,
                keccak256(spec.depositNoteData),
                keccak256(spec.depositPolicyData),
                spec.minOut,
                spec.routerDeadline
            )
        );
        return uint256(
            keccak256(
                abi.encode(
                    "ERCXXXX_PUBLIC_ACTION_ROUTER_V1",
                    executionChainId,
                    address(this),
                    sourcePool,
                    intentReplayId,
                    spec.tokenIn,
                    spec.amountIn,
                    actionHash,
                    reshieldHash
                )
            )
        ) % FIELD_MODULUS;
    }

    /// @notice Atomically unshield `in.from` -> this router -> (optional action)
    ///         -> reshield into `spec.targetPool`. Permissionless to call, but
    ///         the source pool only pays this router (authorizedSubmitter) for
    ///         the exact spec (downstreamActionCommitment), so any caller can
    ///         only realize the exact move the withdrawing user authorized.
    function executeMove(MoveIn calldata in_, ActionSpec calldata spec) external {
        _enterRun();

        IShieldedPool.PublicInputs calldata pi = in_.publicInputs;

        // Bind the withdrawal to this router and this exact spec.
        require(pi.authorizedSubmitter == uint256(uint160(address(this))), SubmitterNotRouter());
        require(pi.publicRecipientAddress == uint256(uint160(address(this))), RecipientNotRouter());
        require(spec.sourcePool == address(in_.from), SourcePoolMismatch());
        require(pi.publicAmountOut == spec.amountIn, AmountMismatch());
        require(pi.publicTokenAddress == uint256(uint160(spec.tokenIn)), TokenMismatch());
        require(
            pi.downstreamActionCommitment
                == computeDownstreamActionCommitment(
                    pi.executionChainId, address(in_.from), pi.intentReplayId, spec
                ),
            CommitmentMismatch()
        );
        require(block.timestamp <= spec.routerDeadline, RouterDeadlinePassed());

        // Realized output = delta of tokenOut held by this router across the move.
        uint256 inputBalBefore = _balance(spec.tokenIn);
        uint256 outputBalBefore = _balance(spec.tokenOut);

        // 1. Unshield: the source pool pays THIS router (authorizedSubmitter and
        //    publicRecipientAddress both pinned to address(this)).
        in_.from.transact(
            in_.poolProof,
            in_.authProof,
            in_.publicInputs,
            in_.outputNoteData0,
            in_.outputNoteData1,
            in_.outputNoteData2,
            in_.policyData
        );

        // 2. Optional single external action (swap / bridge slot). Forward the
        //    unshielded input to the committed action target so the target can
        //    actually consume it: ETH as call value, ERC-20 as an exact approval
        //    that is reset to 0 afterward. actionTarget, actionCalldata, tokenIn,
        //    and amountIn are all bound by downstreamActionCommitment, so a
        //    third-party submitter cannot redirect the forwarded input.
        if (spec.actionTarget != address(0)) {
            bool ok;
            if (spec.tokenIn == address(0)) {
                (ok,) = spec.actionTarget.call{value: spec.amountIn}(spec.actionCalldata);
            } else {
                _approveExact(spec.tokenIn, spec.actionTarget, spec.amountIn);
                (ok,) = spec.actionTarget.call(spec.actionCalldata);
                _approveExact(spec.tokenIn, spec.actionTarget, 0);
            }
            require(ok, ActionCallFailed());
        }

        uint256 amountOut = _balance(spec.tokenOut) - outputBalBefore;
        require(amountOut >= spec.minOut, InsufficientOutput());

        // 3. Reshield the realized output into the destination pool.
        if (spec.tokenOut == address(0)) {
            IShieldedPool(spec.targetPool).deposit{value: amountOut}(
                address(0),
                amountOut,
                spec.ownerCommitment,
                spec.depositNoteData,
                spec.depositPolicyData
            );
        } else {
            _approveExact(spec.tokenOut, spec.targetPool, amountOut);
            IShieldedPool(spec.targetPool).deposit(
                spec.tokenOut,
                amountOut,
                spec.ownerCommitment,
                spec.depositNoteData,
                spec.depositPolicyData
            );
        }

        require(_balance(spec.tokenIn) == inputBalBefore, ResidualInput());
        require(_balance(spec.tokenOut) == outputBalBefore, ResidualOutput());

        _exitRun();
    }

    /// @dev Accept ETH only during an in-flight executeMove (the withdrawal leg).
    receive() external payable {
        bytes32 slot = RUN_GUARD_SLOT;
        uint256 flag;
        assembly ("memory-safe") {
            flag := tload(slot)
        }
        require(flag == 1, EthNotDuringRun());
    }

    function _balance(address token) private view returns (uint256) {
        if (token == address(0)) return address(this).balance;
        return ERC20AssetLib.balanceOf(token, address(this));
    }

    function _approveExact(address token, address spender, uint256 amount) private {
        (bool success, bytes memory ret) =
            token.call(abi.encodeWithSelector(0x095ea7b3, spender, amount)); // approve(address,uint256)
        require(success, ApprovalFailed());
        if (ret.length != 0) {
            require(abi.decode(ret, (bool)), ApprovalFailed());
        } else {
            require(token.code.length != 0, ApprovalFailed());
        }
    }

    function _enterRun() private {
        bytes32 slot = RUN_GUARD_SLOT;
        uint256 flag;
        assembly ("memory-safe") {
            flag := tload(slot)
        }
        require(flag == 0, ReentrantCall());
        assembly ("memory-safe") {
            tstore(slot, 1)
        }
    }

    function _exitRun() private {
        bytes32 slot = RUN_GUARD_SLOT;
        assembly ("memory-safe") {
            tstore(slot, 0)
        }
    }
}
