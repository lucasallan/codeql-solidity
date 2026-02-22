/**
 * @name Flash loan attack vector detection
 * @description Detects flash loan + governance attack vectors where governance can be manipulated via ERC20 callbacks
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/flash-loan-attack-vector
 * @tags security flash-loan governance solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.callgraph.CallResolution

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
 * Gets the visibility of a function.
 */
string getFunctionVisibility(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility" and
    result = vis.getAChild().getValue()
  )
  or
  not exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility"
  ) and
  result = "public"
}

/**
 * Holds if a function has access control.
 */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%onlyowner%") or
    mod.getValue().toLowerCase().matches("%onlyadmin%") or
    mod.getValue().toLowerCase().matches("%onlyrole%") or
    mod.getValue().toLowerCase().matches("%auth%") or
    mod.getValue().toLowerCase().matches("%authorized%") or
    mod.getValue().toLowerCase().matches("%ownable%") or
    mod.getValue().toLowerCase().matches("%accesscontrol%")
  )
}

/**
 * Holds if `func` is an ERC20 callback (tokensReceived, onTransfer, etc.)
 */
predicate isERC20Callback(Solidity::FunctionDefinition func) {
  exists(string funcName |
    funcName = getFunctionName(func).toLowerCase() |
    funcName = "tokensreceived" or
    funcName = "ontokentransfer" or
    funcName = "onerc20received" or
    funcName = "onerc721received" or
    funcName = "onerc1155received" or
    funcName = "transfercallback" or
    funcName = "uniswapv2call" or
    funcName = "uniswapv3swapcallback"
  )
}

/**
 * Holds if `func` is a governance function (vote, delegate, propose, etc.)
 */
predicate isGovernanceFunction(Solidity::FunctionDefinition func) {
  exists(string funcName |
    funcName = getFunctionName(func).toLowerCase() |
    funcName.matches("%vote%") or
    funcName.matches("%delegate%") or
    funcName.matches("%propose%") or
    funcName.matches("%execute%") or
    funcName.matches("%queue%") or
    funcName.matches("%cast%") or
    funcName.matches("%submit%") or
    funcName.matches("%mint%") or
    funcName.matches("%burn%") and
    not funcName.matches("%nft%")
  )
}

/**
 * Flash loan attack vector: governance functions that can be called directly (no access control)
 *
 * Output: flash_loan_vector|contract|function|entry_point|has_access_control|file:line
 */
string formatFlashLoanVector(Solidity::FunctionDefinition govFunc) {
  exists(Solidity::ContractDeclaration contract |
    govFunc.getParent+() = contract and
    isGovernanceFunction(govFunc) and
    not hasAccessControl(govFunc) and
    getFunctionVisibility(govFunc) in ["external", "public"] and
    result =
      "flash_loan_vector|" + getContractName(contract) + "|" + getFunctionName(govFunc) +
        "|direct|false" +
        "|" + govFunc.getLocation().getFile().getName() + ":" +
        govFunc.getLocation().getStartLine().toString()
  )
}

/**
 * Governance function without access control
 *
 * Output: governance_no_auth|contract|function|file:line
 */
string formatGovernanceNoAuth(Solidity::FunctionDefinition govFunc) {
  exists(Solidity::ContractDeclaration contract |
    govFunc.getParent+() = contract and
    isGovernanceFunction(govFunc) and
    not hasAccessControl(govFunc) and
    getFunctionVisibility(govFunc) in ["external", "public"] and
    result =
      "governance_no_auth|" + getContractName(contract) + "|" + getFunctionName(govFunc) +
        "|" + govFunc.getLocation().getFile().getName() + ":" +
        govFunc.getLocation().getStartLine().toString()
  )
}

/**
 * Token balance manipulation opportunity: governance uses token balance for decisions
 *
 * Output: token_balance_governance|contract|function|decision_type|file:line
 */
string formatTokenBalanceGovernance(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    isGovernanceFunction(func) and
    // Function reads balance
    exists(Solidity::MemberExpression mem |
      mem.getParent+() = func.getBody() |
      mem.getObject().(Solidity::Identifier).getValue() = "balanceOf" or
      mem.getObject().(Solidity::Identifier).getValue() = "balance"
    ) and
    result =
      "token_balance_governance|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|balance_check|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatFlashLoanVector(_)
  or
  info = formatGovernanceNoAuth(_)
  or
  info = formatTokenBalanceGovernance(_)
select info, info
