// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @dev Minimal ERC-7579 module + hook interfaces (no external dependency), per the ERC-7579 spec.
///      MODULE_TYPE_HOOK == 4. A hook's preCheck runs before the account executes; a revert there
///      blocks the execution. That revert is the fail-closed gate this reference is built around.
uint256 constant MODULE_TYPE_HOOK = 4;

interface IModule {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}

interface IHook is IModule {
    /// @notice Called by the smart account BEFORE it executes `msgData`.
    /// @param  msgSender the original caller of the account's execute entrypoint
    /// @param  msgValue  the value forwarded with the execution
    /// @param  msgData   the full calldata the account received (the call to execute(...))
    /// @return hookData  opaque data passed back to postCheck (unused here)
    function preCheck(address msgSender, uint256 msgValue, bytes calldata msgData)
        external
        returns (bytes memory hookData);

    /// @notice Called AFTER execution with the hookData returned by preCheck.
    function postCheck(bytes calldata hookData) external;
}
