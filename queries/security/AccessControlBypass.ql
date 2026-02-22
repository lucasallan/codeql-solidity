/**
 * @name Access Control Bypass Detection
 * @description Detects access control vulnerabilities in sensitive functions
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/access-control-bypass
 * @tags security access control solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Functions with access control. */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  func.getBody().toString().toLowerCase().matches("%onlyowner%") or
  func.getBody().toString().toLowerCase().matches("%require%") or
  func.getBody().toString().toLowerCase().matches("%modifier%") or
  func.getBody().toString().toLowerCase().matches("%auth%") or
  func.getBody().toString().toLowerCase().matches("%role%")
}

from Solidity::FunctionDefinition func
where
  (
    getFunctionName(func).toLowerCase().matches("%set%") or
    getFunctionName(func).toLowerCase().matches("%update%") or
    getFunctionName(func).toLowerCase().matches("%upgrade%") or
    getFunctionName(func).toLowerCase().matches("%withdraw%") or
    getFunctionName(func).toLowerCase().matches("%sweep%") or
    getFunctionName(func).toLowerCase().matches("%initialize%")
  ) and
  not hasAccessControl(func)
select func, "Sensitive function '" + getFunctionName(func) + "' may lack access control"
