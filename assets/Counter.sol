// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Counter
 * @dev 一个简单的计数器合约，用于验证链上写入操作。
 */
contract Counter {
    uint256 public count;

    /**
     * @dev 将计数值加一。
     */
    function increment() public {
        count += 1;
    }

    /**
     * @dev 获取当前的计数值。
     * @return uint256 当前的计数值。
     */
    function get() public view returns (uint256) {
        return count;
    }
}
