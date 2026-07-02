// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {InvinoveritasPolicyHook} from "../src/InvinoveritasPolicyHook.sol";
import {MockVerdictSigVerifier} from "./MockVerdictSigVerifier.sol";
import {MODULE_TYPE_HOOK} from "../src/IERC7579Module.sol";

/// @notice Exercises the policy hook's gate logic against the mock signature verifier.
///         Run: `forge test` (set a remapping for forge-std). The contract under test is also
///         standalone solc-compile-verified.
contract InvinoveritasPolicyHookTest is Test {
    InvinoveritasPolicyHook hook;
    MockVerdictSigVerifier sig;

    address account = address(0xA11CE);
    bytes32 verifier = bytes32(uint256(0x6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7));
    bytes32 strangerKey = bytes32(uint256(0xBEEF));
    bytes mockSig = hex"01"; // opaque; the mock keys validity on the (pubkey,digest,sig) tuple

    // a sample ERC-7579 single execution: transfer-ish call to a target
    bytes32 mode = bytes32(0); // callType byte = 0x00 (single, non-delegatecall)
    address target = address(0xCAFE);
    uint256 value = 1 ether;
    bytes innerCall = hex"a9059cbb"; // e.g. erc20 transfer selector
    bytes executionCalldata;

    function setUp() public {
        sig = new MockVerdictSigVerifier();
        hook = new InvinoveritasPolicyHook(sig);
        executionCalldata = abi.encodePacked(target, value, innerCall);

        // install for `account` with the independent verifier allowlisted
        bytes32[] memory vs = new bytes32[](1);
        vs[0] = verifier;
        vm.prank(account);
        hook.onInstall(abi.encode(vs));
    }

    // Same value as hook.EXECUTE_SELECTOR(), computed locally (pure, no external call) rather than
    // read from the contract — reading it via an external call here made _msgData() itself perform
    // a call, which (when _msgData() is evaluated as an argument right after vm.prank(account))
    // silently consumed the prank before the intended call, e.g. preCheck ran as the test contract
    // instead of `account`. Found + fixed 2026-07-02: this suite had never actually been run with
    // forge before (no forge in the environment previously — only solc-compile-checked), so the bug
    // was latent since it was written.
    bytes4 constant _EXECUTE_SELECTOR = bytes4(keccak256("execute(bytes32,bytes)"));

    function _msgData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(_EXECUTE_SELECTOR, mode, executionCalldata);
    }

    function _digest() internal view returns (bytes32) {
        return hook.computeActionDigest(account, mode, executionCalldata);
    }

    function _recordApprove(uint64 expiry) internal {
        bytes32 d = _digest();
        bytes32 commitment =
            hook.verdictCommitment(account, d, hook.VERDICT_APPROVE(), verifier, expiry);
        sig.setValid(verifier, commitment, mockSig, true);
        hook.recordVerdict(account, d, hook.VERDICT_APPROVE(), verifier, expiry, mockSig);
    }

    function test_ModuleTypeIsHook() public view {
        assertTrue(hook.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(hook.isModuleType(1));
    }

    function test_ApproveUnlocksExactAction() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(account);
        hook.preCheck(account, value, _msgData()); // does not revert
        // consumed
        (, bool consumed,,) = hook.approvalOf(account, _digest());
        assertTrue(consumed);
    }

    function test_RevertWhen_NoVerdict() public {
        vm.prank(account);
        vm.expectRevert(bytes("no independent approve verdict for this exact action"));
        hook.preCheck(account, value, _msgData());
    }

    function test_RevertWhen_RejectVerdict() public {
        bytes32 d = _digest();
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 commitment = hook.verdictCommitment(account, d, 3, verifier, expiry); // 3 = reject
        sig.setValid(verifier, commitment, mockSig, true);
        vm.expectRevert(bytes("not an approve verdict"));
        hook.recordVerdict(account, d, 3, verifier, expiry, mockSig);
    }

    function test_RevertWhen_VerifierNotAllowlisted() public {
        bytes32 d = _digest();
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint8 approve = hook.VERDICT_APPROVE(); // evaluate BEFORE expectRevert — see _msgData() comment
        vm.expectRevert(bytes("verifier not in independence allowlist"));
        hook.recordVerdict(account, d, approve, strangerKey, expiry, mockSig);
    }

    function test_RevertWhen_BadSignature() public {
        bytes32 d = _digest();
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint8 approve = hook.VERDICT_APPROVE(); // see comment above
        // do NOT mark the tuple valid in the mock
        vm.expectRevert(bytes("verdict signature invalid"));
        hook.recordVerdict(account, d, approve, verifier, expiry, mockSig);
    }

    function test_RevertWhen_DigestMismatch_BindingHolds() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        // now try to execute a DIFFERENT action (different inner call) under the same approval
        executionCalldata = abi.encodePacked(target, value, hex"deadbeef");
        vm.prank(account);
        vm.expectRevert(bytes("no independent approve verdict for this exact action"));
        hook.preCheck(account, value, _msgData());
    }

    function test_RevertWhen_Expired() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);
        _recordApprove(expiry);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(account);
        vm.expectRevert(bytes("verdict expired"));
        hook.preCheck(account, value, _msgData());
    }

    function test_RevertWhen_Replay() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        vm.prank(account);
        hook.preCheck(account, value, _msgData());
        vm.prank(account);
        vm.expectRevert(bytes("verdict already consumed"));
        hook.preCheck(account, value, _msgData());
    }

    function test_RevertWhen_Delegatecall() public {
        _recordApprove(uint64(block.timestamp + 1 hours));
        // flip the call-type byte (most-significant byte of mode) to 0xff = delegatecall
        mode = bytes32(uint256(0xff) << 248);
        executionCalldata = abi.encodePacked(target, value, innerCall);
        vm.prank(account);
        vm.expectRevert(bytes("delegatecall not permitted by policy"));
        hook.preCheck(account, value, _msgData());
    }

    function test_RevertWhen_NotInstalled() public {
        address other = address(0xB0B);
        vm.prank(other);
        vm.expectRevert(bytes("policy hook not installed for this account"));
        hook.preCheck(other, value, _msgData());
    }
}
