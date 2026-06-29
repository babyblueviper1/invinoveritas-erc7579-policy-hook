// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title IVerdictSigVerifier
/// @notice Abstracts signature verification so the policy hook is agnostic to the curve/scheme.
///
/// invinoveritas verdict proofs are canonically BIP-340 (schnorr over secp256k1, NIP-01 Nostr
/// events) — the SAME signature you re-verify off-chain for free at /verify-proof. EVM has no
/// schnorr precompile, so on-chain verification is delegated to a verifier contract. Wire one of
/// the public BIP-340 secp256k1 verifiers we have been reviewing in the trustless-ai ecosystem:
///   - verklegarden/crysol (BIP-340)         - chronicleprotocol/scribe
///   - witnet/elliptic-curve-solidity        (or any audited equivalent)
/// behind this interface at install time. A `MockVerdictSigVerifier` is provided for tests.
///
/// @dev `pubkey` is the 32-byte x-only secp256k1 key (the Nostr/`verifier_pubkey`). `digest` is the
///      32-byte message the signature commits to (see InvinoveritasPolicyHook.verdictCommitment).
interface IVerdictSigVerifier {
    function verify(bytes32 pubkey, bytes32 digest, bytes calldata signature) external view returns (bool);
}
