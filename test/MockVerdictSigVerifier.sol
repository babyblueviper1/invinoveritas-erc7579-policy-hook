// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IVerdictSigVerifier} from "../src/IVerdictSigVerifier.sol";

/// @notice Test double for IVerdictSigVerifier. Lets a test register the exact
///         (pubkey, digest, signature) tuples it considers valid, so the hook's
///         policy logic can be exercised without a live BIP-340 verifier.
///         In production this is replaced by an audited on-chain schnorr/BIP-340 verifier.
contract MockVerdictSigVerifier is IVerdictSigVerifier {
    mapping(bytes32 => bool) private _valid;

    function _key(bytes32 pubkey, bytes32 digest, bytes memory signature) private pure returns (bytes32) {
        return keccak256(abi.encode(pubkey, digest, signature));
    }

    function setValid(bytes32 pubkey, bytes32 digest, bytes calldata signature, bool ok) external {
        _valid[_key(pubkey, digest, signature)] = ok;
    }

    function verify(bytes32 pubkey, bytes32 digest, bytes calldata signature) external view override returns (bool) {
        return _valid[_key(pubkey, digest, signature)];
    }
}
