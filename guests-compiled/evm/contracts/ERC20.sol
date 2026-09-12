// SPDX-License-Identifier: MIT
// A self-contained ERC-20 with OpenZeppelin v4's storage layout (`_balances` slot 0,
// `_allowances` slot 1, `_totalSupply` slot 2) and its two events, compiled once with the pinned
// `solc` recorded in SOLC.md; only the *runtime* bytecode is committed (`erc20.runtime.hex`) and
// the M4.3 guest executes that alone — there is no constructor to run, so the exit test seeds
// `_balances[ALICE]` and `_totalSupply` as storage witnesses in the pre-state tree instead
// (`research/src/evm.rs::erc20_transfer`).
//
// The `require` messages are kept (rather than custom errors) so the revert path returns ABI
// string data the test can read back out of the public output's return-data hash.
pragma solidity 0.8.37;

contract ERC20 {
    mapping(address => uint256) private _balances;                       // slot 0
    mapping(address => mapping(address => uint256)) private _allowances; // slot 1
    uint256 private _totalSupply;                                        // slot 2

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function totalSupply() external view returns (uint256) { return _totalSupply; }

    function balanceOf(address a) external view returns (uint256) { return _balances[a]; }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address o, address s) external view returns (uint256) { return _allowances[o][s]; }

    function approve(address s, uint256 amount) external returns (bool) {
        _allowances[msg.sender][s] = amount;
        emit Approval(msg.sender, s, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = _allowances[from][msg.sender];
        require(a >= amount, "ERC20: insufficient allowance");
        _allowances[from][msg.sender] = a - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "ERC20: transfer to the zero address");
        uint256 b = _balances[from];
        require(b >= amount, "ERC20: transfer amount exceeds balance");
        _balances[from] = b - amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
