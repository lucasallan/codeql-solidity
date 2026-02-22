/**
 * @name Missing access control
 * @description Detects functions that may be missing access control
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/missing-access-control
 * @tags security access control solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Holds if function has access control. */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  func.getBody().toString().toLowerCase().matches("%onlyowner%") or
  func.getBody().toString().toLowerCase().matches("%require%") or
  func.getBody().toString().toLowerCase().matches("%modifier%") or
  func.getBody().toString().toLowerCase().matches("%auth%") or
  func.getBody().toString().toLowerCase().matches("%role%")
}

/** Sensitive functions that should have access control. */
from Solidity::FunctionDefinition func
where
  (
    getFunctionName(func).toLowerCase().matches("%set%") or
    getFunctionName(func).toLowerCase().matches("%withdraw%") or
    getFunctionName(func).toLowerCase().matches("%mint%") or
    getFunctionName(func).toLowerCase().matches("%burn%") or
    getFunctionName(func).toLowerCase().matches("%upgrade%") or
    getFunctionName(func).toLowerCase().matches("%pause%") or
    getFunctionName(func).toLowerCase().matches("%sweep%")
  ) and
  not hasAccessControl(func)
select func, "Sensitive function '" + getFunctionName(func) + "' may lack access control"
