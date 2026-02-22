/**
 * @name Delegatecall storage collision detection
 * @description Detects proxy patterns vulnerable to storage collisions due to mismatched variable ordering
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/delegatecall-storage-collision
 * @tags security proxy storage-collision solidity
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
 * Holds if `call` is a delegatecall.
 */
private predicate isDelegatecall(Solidity::CallExpression call) {
  ExternalCalls::isDelegateCall(call)
}

/**
 * Gets the state variables of a contract.
 */
string formatStateVariable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string varType |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    varType = var.getType().(Solidity::AstNode).toString() and
    result =
      "state_var|" + getContractName(contract) + "|" + varName + "|" + varType +
        "|" + var.getLocation().getStartLine().toString()
  )
}

/**
 * Delegatecall detection
 *
 * Output: delegatecall|contract|function|file:line
 */
string formatDelegatecall(Solidity::CallExpression call) {
  isDelegatecall(call) and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    call.getParent+() = func and
    func.getParent+() = contract and
    result =
      "delegatecall|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Implementation slot detection
 *
 * Output: impl_slot|contract|variable|file:line
 */
string formatImplementationSlot(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%implementation%") or
      varName.toLowerCase().matches("%logic%") or
      varName.toLowerCase().matches("%target%")
    ) and
    result =
      "impl_slot|" + getContractName(contract) + "|" + varName +
        "|" + var.getLocation().getFile().getName() + ":" +
        var.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatStateVariable(_)
  or
  info = formatDelegatecall(_)
  or
  info = formatImplementationSlot(_)
select info, info
