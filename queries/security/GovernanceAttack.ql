/**
 * @name Governance Attack Detection
 * @description Detects governance functions that may lack timelock checks
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/security/governance-attack
 * @tags security governance solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Governance functions without timelock. */
from Solidity::FunctionDefinition func
where
  (
    getFunctionName(func).toLowerCase().matches("%propose%") or
    getFunctionName(func).toLowerCase().matches("%vote%") or
    getFunctionName(func).toLowerCase().matches("%execute%") or
    getFunctionName(func).toLowerCase().matches("%delegate%") or
    getFunctionName(func).toLowerCase().matches("%cast%")
  ) and
  not func.getBody().toString().toLowerCase().matches("%timelock%") and
  not func.getBody().toString().toLowerCase().matches("%delay%")
select func, "Governance function '" + getFunctionName(func) + "' without timelock check - susceptible to flash loan attacks"
