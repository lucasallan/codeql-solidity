/**
 * @name Timestamp dependence
 * @description Detects usage of block.timestamp which can be manipulated by miners
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/security/timestamp
 * @tags security timestamp block solidity
 */

import codeql.solidity.ast.internal.TreeSitter

from Solidity::FunctionDefinition func
where func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%update%") or
      func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%timelock%") or
      func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%lock%")
select func, "Block timestamp can be manipulated by miners within certain limits. Avoid relying on it for critical logic."
