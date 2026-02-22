/**
 * @name Value Flow / Asset Custody Analysis
 * @description Identifies functions that handle value transfers without access control
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/value-flow-theft
 * @tags security value solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Value exit functions without access control. */
from Solidity::FunctionDefinition func
where
  (
    getFunctionName(func).toLowerCase().matches("%withdraw%") or
    getFunctionName(func).toLowerCase().matches("%redeem%") or
    getFunctionName(func).toLowerCase().matches("%unstake%") or
    getFunctionName(func).toLowerCase().matches("%transfer%") or
    getFunctionName(func).toLowerCase().matches("%sweep%") or
    getFunctionName(func).toLowerCase().matches("%claim%")
  ) and
  not func.getBody().toString().toLowerCase().matches("%onlyowner%") and
  not func.getBody().toString().toLowerCase().matches("%require%") and
  not func.getBody().toString().toLowerCase().matches("%modifier%") and
  not func.getBody().toString().toLowerCase().matches("%auth%")
select func, "Value exit function '" + getFunctionName(func) + "' may lack access control - potential theft vector"
