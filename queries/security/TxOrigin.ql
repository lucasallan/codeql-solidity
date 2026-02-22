/**
 * @name tx.origin usage
 * @description Detects usage of tx.origin for authorization which is vulnerable to phishing
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id solidity/security/tx-origin
 * @tags security tx.origin authorization solidity
 */

import codeql.solidity.ast.internal.TreeSitter

from Solidity::FunctionDefinition func
where func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%authorized%") or
      func.getName().(Solidity::Identifier).getValue().toLowerCase().matches("%sensitive%")
select func, "Use of tx.origin for authorization is vulnerable to phishing attacks. Use msg.sender instead."
