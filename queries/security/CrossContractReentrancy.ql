/**
 * @name Cross-contract reentrancy detection
 * @description Detects cross-contract reentrancy patterns where Contract A calls Contract B, which can callback into Contract A
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/cross-contract-reentrancy
 * @tags security reentrancy cross-contract solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Holds if a function has a reentrancy guard modifier.
 */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%nonreentrant%") or
    mod.getValue().toLowerCase().matches("%lock%") or
    mod.getValue().toLowerCase().matches("%mutex%") or
    mod.getValue().toLowerCase().matches("%guard%")
  )
}

/**
 * Holds if `call` is an external call (low-level, contract reference, or ether transfer).
 */
private predicate isExternalCall(Solidity::CallExpression call) {
  ExternalCalls::isLowLevelCall(call) or
  ExternalCalls::isContractReferenceCall(call) or
  ExternalCalls::isEtherTransfer(call)
}

/**
 * Holds if `func` is a callback/hook function that can be invoked by external contracts.
 */
predicate isCallbackFunction(Solidity::FunctionDefinition func) {
  exists(string funcName |
    funcName = getFunctionName(func).toLowerCase() |
    funcName.matches("%callback%") or
    funcName.matches("%hook%") or
    funcName.matches("%received%") or
    funcName = "tokensreceived" or
    funcName = "ontokentransfer" or
    funcName = "onerc721received" or
    funcName = "onerc1155received" or
    funcName.matches("%uniswapv2call%") or
    funcName.matches("%uniswapv3swapcallback%") or
    funcName.matches("%flashloan%") or
    funcName = "receive" or
    funcName = "fallback"
  )
}

/**
 * Functions with external calls that lack reentrancy guards (baseline for cross-contract analysis)
 *
 * Output format: unguarded_external_call|caller_contract|caller_func|call_line
 */
string formatUnguardedExternalCalls(
  Solidity::CallExpression extCall,
  Solidity::FunctionDefinition callerFunc,
  Solidity::ContractDeclaration callerContract
) {
  isExternalCall(extCall) and
  extCall.getParent+() = callerFunc and
  callerFunc.getParent+() = callerContract and
  not hasReentrancyGuard(callerFunc) and
  result =
    "unguarded_external_call|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) +
      "|" + extCall.getLocation().getFile().getName() + ":" + extCall.getLocation().getStartLine().toString()
}

/**
 * Receive/fallback function detection (reentrancy entry points)
 *
 * Output format: callback|contract|function_type|file:line
 */
string formatCallback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func).toLowerCase() and
    (funcName = "receive" or funcName = "fallback") and
    result =
      "callback|" + getContractName(contract) + "|" + funcName +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * ERC20 callback detection
 *
 * Output format: erc20_callback|contract|function|file:line
 */
string formatERC20Callback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func).toLowerCase() and
    (
      funcName = "tokensreceived" or
      funcName = "ontokentransfer" or
      funcName = "onerc721received" or
      funcName = "onerc1155received" or
      funcName.matches("%uniswapv2call%") or
      funcName.matches("%uniswapv3swapcallback%")
    ) and
    result =
      "erc20_callback|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

// Main query - collect all cross-contract reentrancy patterns
from string info
where
  info = formatUnguardedExternalCalls(_, _, _)
  or
  info = formatCallback(_)
  or
  info = formatERC20Callback(_)
select info, info
