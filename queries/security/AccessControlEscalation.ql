/**
 * @name Access control escalation detection
 * @description Detects access control escalation patterns: missing auth → state modification → external call
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/access-control-escalation
 * @tags security access-control solidity
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
 * Gets the visibility of a function.
 */
string getFunctionVisibility(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility" and
    result = vis.getAChild().getValue()
  )
  or
  not exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility"
  ) and
  result = "public"
}

/**
 * Holds if a function has an access control modifier.
 */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%onlyowner%") or
    mod.getValue().toLowerCase().matches("%onlyadmin%") or
    mod.getValue().toLowerCase().matches("%onlyrole%") or
    mod.getValue().toLowerCase().matches("%auth%") or
    mod.getValue().toLowerCase().matches("%authorized%") or
    mod.getValue().toLowerCase().matches("%ownable%") or
    mod.getValue().toLowerCase().matches("%accesscontrol%") or
    mod.getValue().toLowerCase().matches("%pausable%")
  )
}

/**
 * Holds if a function checks msg.sender in its body.
 */
predicate checksMsgSender(Solidity::FunctionDefinition func) {
  exists(Solidity::MemberExpression m |
    m.getParent+() = func.getBody() |
    m.getObject().(Solidity::Identifier).getValue() = "msg" and
    m.getProperty().(Solidity::AstNode).getValue() = "sender"
  )
}

/**
 * Holds if a function has any access control (modifier or msg.sender check).
 */
predicate hasAccessControlCheck(Solidity::FunctionDefinition func) {
  hasAccessControl(func) or checksMsgSender(func)
}

/**
 * Holds if `node` modifies a state variable.
 */
predicate modifiesState(Solidity::AstNode node) {
  // Assignment
  exists(Solidity::AssignmentExpression assign |
    node = assign or
    assign.getParent+() = node.getParent+()
  )
  or
  // Update expression (++, --)
  exists(Solidity::UpdateExpression update |
    node = update or
    update.getParent+() = node.getParent+()
  )
  or
  // Delete
  exists(Solidity::UnaryExpression unary |
    node = unary and
    unary.getOperator().(Solidity::AstNode).getValue() = "delete"
  )
  or
  // Array push/pop
  exists(Solidity::CallExpression call, Solidity::MemberExpression mem |
    node = call and
    call.getFunction() = mem and
    mem.getProperty().(Solidity::AstNode).getValue() in ["push", "pop"]
  )
}

/**
 * Holds if `call` is an external call.
 */
private predicate isExternalCall(Solidity::CallExpression call) {
  ExternalCalls::isLowLevelCall(call) or
  ExternalCalls::isContractReferenceCall(call) or
  ExternalCalls::isEtherTransfer(call)
}

/**
 * Access control escalation pattern:
 * - Missing access control check
 * - Contains state modification
 * - Contains external call
 *
 * Output: access_escalation|contract|function|vulnerability_chain|visibility|file:line
 */
string formatAccessEscalation(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    // Has state modification
    exists(Solidity::AstNode node |
      node.getParent+() = func.getBody() and
      modifiesState(node)
    ) and
    // Has external call
    exists(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      isExternalCall(call)
    ) and
    // Only external/public functions are concerning
    getFunctionVisibility(func) in ["external", "public"] and
    result =
      "access_escalation|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|no_auth_state_mod_external_call|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Missing access control on sensitive functions (with external call)
 *
 * Output: missing_access_control|contract|function|sensitivity|visibility|file:line
 */
string formatMissingAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string sensitivity |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      // Sensitive function names
      (
        getFunctionName(func).toLowerCase().matches("%admin%") or
        getFunctionName(func).toLowerCase().matches("%owner%") or
        getFunctionName(func).toLowerCase().matches("%upgrade%") or
        getFunctionName(func).toLowerCase().matches("%set%") or
        getFunctionName(func).toLowerCase().matches("%withdraw%") or
        getFunctionName(func).toLowerCase().matches("%transfer%") or
        getFunctionName(func).toLowerCase().matches("%mint%") or
        getFunctionName(func).toLowerCase().matches("%burn%") or
        getFunctionName(func).toLowerCase().matches("%pause%") or
        getFunctionName(func).toLowerCase().matches("%unpause%") or
        getFunctionName(func).toLowerCase().matches("%grant%") or
        getFunctionName(func).toLowerCase().matches("%revoke%")
      ) and
      sensitivity = "high"
      or
      // Has external call (potential for escalation)
      (
        exists(Solidity::CallExpression call |
          call.getParent+() = func.getBody() and
          isExternalCall(call)
        )
      ) and
      sensitivity = "medium"
    ) and
    result =
      "missing_access_control|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + sensitivity + "|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * State-modifying function without access control
 *
 * Output: unprotected_state_mod|contract|function|visibility|file:line
 */
string formatUnprotectedStateMod(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    getFunctionVisibility(func) in ["external", "public"] and
    exists(Solidity::AstNode node |
      node.getParent+() = func.getBody() and
      modifiesState(node)
    ) and
    result =
      "unprotected_state_mod|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * External call without access control
 *
 * Output: unprotected_external_call|contract|function|visibility|file:line
 */
string formatUnprotectedExternalCall(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    getFunctionVisibility(func) in ["external", "public"] and
    exists(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      isExternalCall(call)
    ) and
    result =
      "unprotected_external_call|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatAccessEscalation(_)
  or
  info = formatMissingAccessControl(_)
  or
  info = formatUnprotectedStateMod(_)
  or
  info = formatUnprotectedExternalCall(_)
select info, info
