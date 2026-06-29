// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IHook, IModule, MODULE_TYPE_HOOK} from "./IERC7579Module.sol";
import {IVerdictSigVerifier} from "./IVerdictSigVerifier.sol";

/// @title InvinoveritasPolicyHook
/// @notice An ERC-7579 hook module that turns an *independent, recomputable* invinoveritas `/review`
///         verdict into an on-chain, fail-closed pre-execution gate for a modular smart account.
///
/// The thing a smart account cannot self-serve is an independent second opinion on its own proposed
/// transaction — you can't self-issue a verdict a third party trusts. This module enforces that one
/// has been issued, by a party that is NOT the account, and that it binds to the *exact* execution
/// about to run.
///
/// ## What makes it evidence and not an attestation
///  1. **Recompute, don't trust.** `preCheck` derives the action digest from the ACTUAL execution the
///     account is about to perform (chainId, account, mode, executionCalldata) — never from a value
///     handed in by the caller. The recorded approval must bind to that recomputed digest or the
///     execution reverts.
///  2. **Independence.** A verdict only counts if its signing key is in the account's
///     independent-verifier allowlist AND the signature verifies. A self-signed receipt cannot unlock
///     execution — that is the whole point.
///  3. **Fail-closed.** No matching, unexpired, unconsumed approve-verdict => `preCheck` reverts =>
///     the account does not execute. (This is the settlement-side mirror of governance-gate-core's
///     `failMode: "closed"` for irreversible actions.)
///
/// ## Layering note (honest)
/// The CANONICAL invinoveritas proof is the full BIP-340-signed NIP-01 Nostr event, Bitcoin-anchored
/// on the public /ledger and re-verifiable for free at /verify-proof. EVM cannot cheaply recompute a
/// JSON Nostr event id, so on-chain this module verifies a compact commitment to the SAME
/// (actionDigest, verdict, verifier_pubkey) triple via an injected `IVerdictSigVerifier` (wire a
/// public BIP-340 secp256k1 verifier). The off-chain canonical proof remains the source of truth;
/// this is its on-chain-enforceable projection. The attestation MUST be produced over this module's
/// `verdictCommitment(...)` preimage — see the README.
contract InvinoveritasPolicyHook is IHook {
    // ---- verdict codes (mirror the off-chain Verdict enum; only "approve" classes unlock) ----
    uint8 public constant VERDICT_APPROVE = 1;
    uint8 public constant VERDICT_APPROVE_WITH_CONCERNS = 2;
    // 3 = reject, 0 = review_unavailable — never unlock execution.

    /// @dev domain separator so a verdict commitment can't be replayed as some other signed message.
    bytes32 public constant VERDICT_DOMAIN = keccak256("invinoveritas.onchain_verdict.v1");

    /// @dev ERC-7579 execute(ModeCode,bytes) selector and the delegatecall call-type byte.
    bytes4 public constant EXECUTE_SELECTOR = bytes4(keccak256("execute(bytes32,bytes)"));
    bytes1 public constant CALLTYPE_DELEGATECALL = 0xff;

    struct Approval {
        bool exists;
        bool consumed; // single-use: a recorded verdict admits exactly one execution
        uint64 expiry;
        bytes32 verifier; // x-only secp256k1 pubkey that signed it
    }

    IVerdictSigVerifier public immutable sigVerifier;

    /// @dev per-account independence allowlist: account => verifier x-only pubkey => allowed.
    mapping(address => mapping(bytes32 => bool)) public independentVerifier;
    /// @dev per-account recorded approvals keyed by the recomputed action digest.
    mapping(address => mapping(bytes32 => Approval)) public approvalOf;
    /// @dev whether the hook has been installed for an account (guards preCheck against an empty allowlist).
    mapping(address => bool) public installed;

    event Installed(address indexed account, uint256 verifierCount);
    event Uninstalled(address indexed account);
    event VerifierSet(address indexed account, bytes32 indexed verifierPubkey, bool allowed);
    event VerdictRecorded(
        address indexed account, bytes32 indexed actionDigest, uint8 verdictCode, bytes32 verifierPubkey, uint64 expiry
    );
    event ActionAdmitted(address indexed account, bytes32 indexed actionDigest, bytes32 verifierPubkey);

    constructor(IVerdictSigVerifier _sigVerifier) {
        require(address(_sigVerifier) != address(0), "sigVerifier=0");
        sigVerifier = _sigVerifier;
    }

    // ---------------------------------------------------------------- ERC-7579 module lifecycle

    /// @param data abi.encode(bytes32[] independentVerifierPubkeys) — the account's initial allowlist.
    function onInstall(bytes calldata data) external override {
        bytes32[] memory verifiers = abi.decode(data, (bytes32[]));
        require(verifiers.length > 0, "allowlist empty: gate would be unconfigurable");
        for (uint256 i; i < verifiers.length; ++i) {
            independentVerifier[msg.sender][verifiers[i]] = true;
            emit VerifierSet(msg.sender, verifiers[i], true);
        }
        installed[msg.sender] = true;
        emit Installed(msg.sender, verifiers.length);
    }

    function onUninstall(bytes calldata) external override {
        installed[msg.sender] = false;
        emit Uninstalled(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    /// @notice The account may adjust its own independence allowlist (msg.sender is the account).
    function setVerifier(bytes32 verifierPubkey, bool allowed) external {
        independentVerifier[msg.sender][verifierPubkey] = allowed;
        emit VerifierSet(msg.sender, verifierPubkey, allowed);
    }

    // ---------------------------------------------------------------- verdict recording

    /// @notice Record a signed, independent approve-verdict for `account` that binds to `actionDigest`.
    ///         Callable by anyone (the signature is the authority, not msg.sender). Single-use.
    function recordVerdict(
        address account,
        bytes32 actionDigest,
        uint8 verdictCode,
        bytes32 verifierPubkey,
        uint64 expiry,
        bytes calldata signature
    ) external {
        require(independentVerifier[account][verifierPubkey], "verifier not in independence allowlist");
        require(verdictCode == VERDICT_APPROVE || verdictCode == VERDICT_APPROVE_WITH_CONCERNS, "not an approve verdict");
        require(block.timestamp <= expiry, "verdict already expired");
        bytes32 commitment = verdictCommitment(account, actionDigest, verdictCode, verifierPubkey, expiry);
        require(sigVerifier.verify(verifierPubkey, commitment, signature), "verdict signature invalid");
        approvalOf[account][actionDigest] = Approval(true, false, expiry, verifierPubkey);
        emit VerdictRecorded(account, actionDigest, verdictCode, verifierPubkey, expiry);
    }

    /// @notice The exact 32-byte preimage an independent verifier must sign for an on-chain verdict.
    ///         Off-chain producers (see README) must sign THIS, over BIP-340, with `verifierPubkey`.
    function verdictCommitment(
        address account,
        bytes32 actionDigest,
        uint8 verdictCode,
        bytes32 verifierPubkey,
        uint64 expiry
    ) public view returns (bytes32) {
        return sha256(
            abi.encode(VERDICT_DOMAIN, block.chainid, address(this), account, actionDigest, verdictCode, verifierPubkey, expiry)
        );
    }

    /// @notice The on-chain action canonicalization: recompute this from the execution you intend to run,
    ///         then obtain a /review verdict whose attestation binds to it. Deterministic, chain-scoped.
    function computeActionDigest(address account, bytes32 mode, bytes calldata executionCalldata)
        public
        view
        returns (bytes32)
    {
        return sha256(abi.encode(block.chainid, account, mode, executionCalldata));
    }

    // ---------------------------------------------------------------- the gate (ERC-7579 hook)

    /// @inheritdoc IHook
    /// @dev msg.sender is the smart account. Reverts (fail-closed) unless a recorded, unexpired,
    ///      unconsumed, independent approve-verdict binds to the recomputed digest of THIS execution.
    function preCheck(address, /*msgSender*/ uint256, /*msgValue*/ bytes calldata msgData)
        external
        override
        returns (bytes memory)
    {
        require(installed[msg.sender], "policy hook not installed for this account");
        require(bytes4(msgData[:4]) == EXECUTE_SELECTOR, "unsupported execution entrypoint");

        // Decode the account's execute(ModeCode mode, bytes executionCalldata) arguments.
        (bytes32 mode, bytes memory executionCalldata) = abi.decode(msgData[4:], (bytes32, bytes));

        // Refuse delegatecall outright — a verdict over a call must never admit a delegatecall.
        require(bytes1(mode) != CALLTYPE_DELEGATECALL, "delegatecall not permitted by policy");

        bytes32 actionDigest = sha256(abi.encode(block.chainid, msg.sender, mode, executionCalldata));

        Approval storage a = approvalOf[msg.sender][actionDigest];
        require(a.exists, "no independent approve verdict for this exact action"); // fail-closed
        require(!a.consumed, "verdict already consumed");
        require(block.timestamp <= a.expiry, "verdict expired");
        a.consumed = true;

        emit ActionAdmitted(msg.sender, actionDigest, a.verifier);
        return "";
    }

    /// @inheritdoc IHook
    function postCheck(bytes calldata) external override {}
}
