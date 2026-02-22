/**
 * @name Oracle Manipulation Detection
 * @description Detects price oracle functions that may lack staleness checks
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/security/oracle-manipulation
 * @tags security oracle solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Oracle functions without staleness check. */
from Solidity::FunctionDefinition func
where
  (
    getFunctionName(func).toLowerCase().matches("%price%") or
    getFunctionName(func).toLowerCase().matches("%oracle%") or
    getFunctionName(func).toLowerCase().matches("%feed%") or
    getFunctionName(func).toLowerCase().matches("%twap%") or
    getFunctionName(func).toLowerCase().matches("%quote%")
  ) and
  not func.getBody().toString().toLowerCase().matches("%stale%") and
  not func.getBody().toString().toLowerCase().matches("%updated%") and
  not func.getBody().toString().toLowerCase().matches("%timestamp%")
select func, "Price oracle function '" + getFunctionName(func) + "' may lack staleness check"
