// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ConnectionTest {
    uint256 private storedData;
    address public owner;

    // Event to emit when data is updated
    event DataUpdated(uint256 newValue, address updater);

    constructor() {
        owner = msg.sender;
    }

    // Set a new value (only owner in this example)
    function set(uint256 _newValue) external {
        storedData = _newValue;
        emit DataUpdated(_newValue, msg.sender);
    }

    // Get the stored value
    function get() external view returns (uint256) {
        return storedData;
    }

    // Check if the contract is alive
    function ping() external pure returns (string memory) {
        return "Pong! Connection successful.";
    }
}