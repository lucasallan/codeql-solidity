/**
 * @name Unchecked low-level call
 * @description Detects unchecked return values on low-level calls
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id solidity/security/unchecked-call
 * @tags security unchecked-call solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Holds if function has return value check. */
predicate hasReturnValueCheck(Solidity::FunctionDefinition func) {
  func.getBody().toString().toLowerCase().matches("%require%") or
  func.getBody().toString().toLowerCase().matches("%assert%") or
  func.getBody().toString().toLowerCase().matches("%if%") or
  func.getBody().toString().toLowerCase().matches("%success%")
}

/** Holds if function has low-level call. */
predicate hasLowLevelCall(Solidity::FunctionDefinition func) {
  func.getBody().toString().toLowerCase().matches("%call%") or
  func.getBody().toString().toLowerCase().matches("%transfer%") or
  func.getBody().toString().toLowerCase().matches("%send%")
}

from Solidity::FunctionDefinition func
where hasLowLevelCall(func) and not hasReturnValueCheck(func)
select func, "Function '" + getFunctionName(func) + "' may have unchecked low-level call return value"
