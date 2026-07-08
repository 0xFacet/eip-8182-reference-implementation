// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {PublicActionRouter} from "../src/PublicActionRouter.sol";
import {IShieldedPool, IShieldedPoolStructs} from "../src/interfaces/IShieldedPool.sol";
import {MockSwapAdapter} from "./mocks/MockSwapAdapter.sol";

/// @notice Minimal ERC20 for the router tests (standard bool-returning API).
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Faithful stand-in for the source pool's transact leg: enforces the
///         section 7.1 submitter authorization and pays the public recipient the
///         withdrawal amount, exactly like ShieldedPool.
contract MockSourcePool {
    error UnauthorizedSubmitter();

    bool public transacted;

    receive() external payable {}

    function transact(
        bytes calldata,
        bytes calldata,
        IShieldedPoolStructs.PublicInputs calldata pi,
        bytes calldata,
        bytes calldata,
        bytes calldata,
        bytes calldata
    ) external {
        // spec section 7.1 submitter gate.
        if (pi.authorizedSubmitter != 0) {
            require(
                msg.sender == address(uint160(pi.authorizedSubmitter)),
                UnauthorizedSubmitter()
            );
        }
        transacted = true;
        address recipient = address(uint160(pi.publicRecipientAddress));
        address token = address(uint160(pi.publicTokenAddress));
        if (token == address(0)) {
            (bool ok,) = recipient.call{value: pi.publicAmountOut}("");
            require(ok, "eth payout failed");
        } else {
            MockERC20(token).transfer(recipient, pi.publicAmountOut);
        }
    }
}

/// @notice Records the reshield call and pulls the deposited value like a real
///         deposit would (the depositor / msg.sender is the router).
contract MockTargetPool {
    bool public deposited;
    address public lastToken;
    uint256 public lastAmount;
    uint256 public lastOwnerCommitment;
    address public lastDepositor;
    bytes32 public lastNoteDataHash;
    bytes32 public lastPolicyDataHash;

    function deposit(
        address token,
        uint256 amount,
        uint256 ownerCommitment,
        bytes calldata outputNoteData,
        bytes calldata policyData
    ) external payable {
        deposited = true;
        lastToken = token;
        lastAmount = amount;
        lastOwnerCommitment = ownerCommitment;
        lastDepositor = msg.sender;
        lastNoteDataHash = keccak256(outputNoteData);
        lastPolicyDataHash = keccak256(policyData);
        if (token == address(0)) {
            require(msg.value == amount, "eth deposit mismatch");
        } else {
            require(msg.value == 0, "unexpected eth");
            MockERC20(token).transferFrom(msg.sender, address(this), amount);
        }
    }
}

contract PublicActionRouterTest is Test {
    PublicActionRouter internal router;
    MockSourcePool internal fromPool;
    MockTargetPool internal toPool;
    MockERC20 internal token;
    MockERC20 internal tokenOut;
    MockSwapAdapter internal swap;

    uint256 internal constant AMOUNT = 700;
    uint256 internal constant OWNER_COMMITMENT = 0x1234;
    uint256 internal constant REPLAY_ID = 0xabcd;

    address internal constant ATTACKER = address(0xBAD);

    function setUp() public {
        router = new PublicActionRouter();
        fromPool = new MockSourcePool();
        toPool = new MockTargetPool();
        token = new MockERC20();
        tokenOut = new MockERC20();
        swap = new MockSwapAdapter();
        vm.warp(1_000_000);
    }

    // ---- builders --------------------------------------------------------

    function _spec(address tokenInOut, uint256 deadline)
        internal
        view
        returns (PublicActionRouter.ActionSpec memory spec)
    {
        spec.sourcePool = address(fromPool);
        spec.tokenIn = tokenInOut;
        spec.amountIn = AMOUNT;
        spec.targetPool = address(toPool);
        spec.tokenOut = tokenInOut; // same-asset move
        spec.ownerCommitment = OWNER_COMMITMENT;
        spec.depositNoteData = hex"deadbeef";
        spec.depositPolicyData = hex"cafe";
        spec.minOut = AMOUNT;
        spec.routerDeadline = deadline;
        spec.actionTarget = address(0);
        spec.actionCalldata = hex"";
    }

    function _pi(PublicActionRouter.ActionSpec memory spec)
        internal
        view
        returns (IShieldedPoolStructs.PublicInputs memory pi)
    {
        pi.publicAmountOut = spec.amountIn;
        pi.publicRecipientAddress = uint256(uint160(address(router)));
        pi.publicTokenAddress = uint256(uint160(spec.tokenIn));
        pi.intentReplayId = REPLAY_ID;
        pi.executionChainId = block.chainid;
        pi.authorizedSubmitter = uint256(uint160(address(router)));
        pi.downstreamActionCommitment = router.computeDownstreamActionCommitment(
            block.chainid, address(fromPool), REPLAY_ID, spec
        );
    }

    function _moveIn(IShieldedPoolStructs.PublicInputs memory pi)
        internal
        view
        returns (PublicActionRouter.MoveIn memory in_)
    {
        in_.from = IShieldedPool(address(fromPool));
        in_.publicInputs = pi;
        in_.poolProof = hex"aa";
        in_.authProof = hex"bb";
        in_.outputNoteData0 = hex"01";
        in_.outputNoteData1 = hex"02";
        in_.outputNoteData2 = hex"03";
        in_.policyData = hex"";
    }

    // ---- happy path ------------------------------------------------------

    function test_happySameAssetEthMove() public {
        vm.deal(address(fromPool), AMOUNT);
        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp + 3600);
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        router.executeMove(in_, spec);

        assertTrue(fromPool.transacted(), "unshield executed");
        assertTrue(toPool.deposited(), "reshield executed");
        assertEq(toPool.lastToken(), address(0), "deposit token");
        assertEq(toPool.lastAmount(), AMOUNT, "deposit amount");
        assertEq(toPool.lastOwnerCommitment(), OWNER_COMMITMENT, "deposit ownerCommitment");
        assertEq(toPool.lastDepositor(), address(router), "depositor is the router");
        assertEq(toPool.lastNoteDataHash(), keccak256(hex"deadbeef"), "deposit note data");
        assertEq(toPool.lastPolicyDataHash(), keccak256(hex"cafe"), "deposit policy data");
        assertEq(address(toPool).balance, AMOUNT, "destination funded");
        assertEq(address(router).balance, 0, "router holds no ETH");
    }

    function test_happySameAssetErc20Move() public {
        token.mint(address(fromPool), AMOUNT);
        PublicActionRouter.ActionSpec memory spec = _spec(address(token), block.timestamp + 3600);
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        router.executeMove(in_, spec);

        assertEq(token.balanceOf(address(toPool)), AMOUNT, "destination funded");
        assertEq(token.balanceOf(address(router)), 0, "router holds no token");
        assertEq(token.allowance(address(router), address(toPool)), 0, "no dangling approval");
    }

    // ---- front-run guard -------------------------------------------------

    /// @notice An attacker who copies the withdrawal and submits it directly to
    ///         the pool (bypassing the router) is rejected: authorizedSubmitter
    ///         is pinned to the router, so the pool reverts UnauthorizedSubmitter
    ///         before consuming the victim's nullifiers.
    function test_frontRunDirectPoolCallReverts() public {
        vm.deal(address(fromPool), AMOUNT);
        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp + 3600);
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        vm.prank(ATTACKER);
        vm.expectRevert(MockSourcePool.UnauthorizedSubmitter.selector);
        fromPool.transact(
            in_.poolProof,
            in_.authProof,
            in_.publicInputs,
            in_.outputNoteData0,
            in_.outputNoteData1,
            in_.outputNoteData2,
            in_.policyData
        );
    }

    /// @notice A caller who tampers with the spec (e.g. redirects the reshield to
    ///         their own ownerCommitment) yields a different commitment than the
    ///         one bound into the pool proof, so executeMove reverts before the
    ///         withdrawal executes.
    function test_wrongSpecCommitmentMismatch() public {
        vm.deal(address(fromPool), AMOUNT);
        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp + 3600);
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec); // commitment for the honest spec

        // Attacker substitutes a spec redirecting to their own note.
        PublicActionRouter.ActionSpec memory tampered = spec;
        tampered.ownerCommitment = OWNER_COMMITMENT + 1;
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        vm.expectRevert(PublicActionRouter.CommitmentMismatch.selector);
        router.executeMove(in_, tampered);
    }

    function test_wrongSubmitterReverts() public {
        vm.deal(address(fromPool), AMOUNT);
        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp + 3600);
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        pi.authorizedSubmitter = uint256(uint160(ATTACKER)); // not the router
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        vm.expectRevert(PublicActionRouter.SubmitterNotRouter.selector);
        router.executeMove(in_, spec);
    }

    // ---- deadline --------------------------------------------------------

    function test_deadlinePassedReverts() public {
        vm.deal(address(fromPool), AMOUNT);
        // Deadline in the past; commitment is computed over the same deadline so
        // the commitment check passes and the deadline check is reached.
        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp - 1);
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        vm.expectRevert(PublicActionRouter.RouterDeadlinePassed.selector);
        router.executeMove(in_, spec);
    }

    // ---- minOut ----------------------------------------------------------

    function test_insufficientOutputReverts() public {
        vm.deal(address(fromPool), AMOUNT);
        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp + 3600);
        spec.minOut = AMOUNT + 1; // demand more than the realized output
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        vm.expectRevert(PublicActionRouter.InsufficientOutput.selector);
        router.executeMove(in_, spec);
    }

    // ---- §17 swap-reshield with variable output --------------------------

    /// @notice ETH -> ETH through an external action that returns a reduced,
    ///         runtime-determined amount (a haircut). The router forwards the
    ///         unshielded ETH as call value, then reshields the realized output.
    ///         This is the variable-output case: the reshield amount is not known
    ///         at plan time, so a conforming wallet would use a
    ///         DEPOSIT_USES_EVENT_PUBLICS payload (asserted off-chain).
    function test_swapReshieldEthVariableOutput() public {
        vm.deal(address(fromPool), AMOUNT);
        uint256 feeBps = 500; // 5% haircut
        uint256 expectedOut = AMOUNT - (AMOUNT * feeBps) / 10_000; // 665

        PublicActionRouter.ActionSpec memory spec = _spec(address(0), block.timestamp + 3600);
        spec.actionTarget = address(swap);
        spec.actionCalldata = abi.encodeWithSelector(MockSwapAdapter.ethHaircut.selector, feeBps);
        spec.minOut = expectedOut;
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        router.executeMove(in_, spec);

        assertEq(toPool.lastAmount(), expectedOut, "reshielded the realized (post-haircut) amount");
        assertEq(address(toPool).balance, expectedOut, "destination funded with realized output");
        assertEq(address(router).balance, 0, "router holds no ETH");
        assertEq(address(swap).balance, AMOUNT - expectedOut, "adapter kept the fee");
        assertEq(toPool.lastOwnerCommitment(), OWNER_COMMITMENT, "output to committed owner, not submitter");
    }

    /// @notice ERC-20 -> different ERC-20 through an external action. Exercises
    ///         the router's exact-approval forwarding of tokenIn and reset.
    function test_swapReshieldErc20VariableOutput() public {
        token.mint(address(fromPool), AMOUNT); // tokenIn liquidity in the source pool
        uint256 realizedOut = 640; // adapter's fixed conversion output
        tokenOut.mint(address(swap), realizedOut); // adapter's tokenOut reserve

        PublicActionRouter.ActionSpec memory spec = _spec(address(token), block.timestamp + 3600);
        spec.tokenOut = address(tokenOut);
        spec.actionTarget = address(swap);
        spec.actionCalldata =
            abi.encodeWithSelector(MockSwapAdapter.erc20Swap.selector, address(token), AMOUNT, address(tokenOut), realizedOut);
        spec.minOut = realizedOut;
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        router.executeMove(in_, spec);

        assertEq(tokenOut.balanceOf(address(toPool)), realizedOut, "destination funded with tokenOut");
        assertEq(token.balanceOf(address(router)), 0, "router forwarded all tokenIn");
        assertEq(tokenOut.balanceOf(address(router)), 0, "router reshielded all tokenOut");
        assertEq(token.allowance(address(router), address(swap)), 0, "tokenIn approval reset");
        assertEq(toPool.lastToken(), address(tokenOut), "reshield token is tokenOut");
    }

    function test_partialErc20InputConsumptionReverts() public {
        token.mint(address(fromPool), AMOUNT);
        uint256 partialIn = AMOUNT - 100;
        uint256 realizedOut = 640;
        tokenOut.mint(address(swap), realizedOut);

        PublicActionRouter.ActionSpec memory spec = _spec(address(token), block.timestamp + 3600);
        spec.tokenOut = address(tokenOut);
        spec.actionTarget = address(swap);
        spec.actionCalldata = abi.encodeWithSelector(
            MockSwapAdapter.erc20Swap.selector, address(token), partialIn, address(tokenOut), realizedOut
        );
        spec.minOut = realizedOut;
        IShieldedPoolStructs.PublicInputs memory pi = _pi(spec);
        PublicActionRouter.MoveIn memory in_ = _moveIn(pi);

        vm.expectRevert(PublicActionRouter.ResidualInput.selector);
        router.executeMove(in_, spec);
    }
}
