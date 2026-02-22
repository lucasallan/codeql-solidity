/**
 * @name Reentrancy vulnerability
 * @description Detects potential reentrancy vulnerabilities where state is changed after external call
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id solidity/security/reentrancy
 * @tags security reentrancy solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::Identifier).getValue()
}

/** Holds if a function has a reentrancy guard. */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%nonreentrant%") or
    mod.getValue().toLowerCase().matches("%lock%") or
    mod.getValue().toLowerCase().matches("%mutex%") or
    mod.getValue().toLowerCase().matches("%guard%")
  )
}

/** Holds if function has external call pattern in name. */
predicate hasExternalCallPattern(Solidity::FunctionDefinition func) {
  func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%withdraw%") or
  func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%transfer%") or
  func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%send%") or
  func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%call%")
}

/** Functions that may be vulnerable to reentrancy. */
from Solidity::FunctionDefinition func
where
  hasExternalCallPattern(func) and
  not hasReentrancyGuard(func)
select func, "Potential reentrancy vulnerability in function '" + getFunctionName(func) + "'"
