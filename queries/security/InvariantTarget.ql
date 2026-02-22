/**
 * @name Invariant target detection
 * @description Identifies functions suitable for invariant testing with Echidna/Halmos
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/analysis/invariant-target
 * @tags analysis invariant testing solidity
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
 * Gets the state variables of a contract as a comma-separated string.
 */
string getStateVars(Solidity::ContractDeclaration contract) {
  exists(string vars |
    vars = concat(Solidity::StateVariableDeclaration v |
      v.getParent+() = contract |
      v.getName().(Solidity::AstNode).getValue(), ", "
    ) and
    result = vars
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
 * Holds if a function has an access control modifier.
 */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%onlyowner%") or
    mod.getValue().toLowerCase().matches("%onlyadmin%") or
    mod.getValue().toLowerCase().matches("%onlyrole%") or
    mod.getValue().toLowerCase().matches("%auth%")
  )
}

/**
 * Holds if a function has a reentrancy guard.
 */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%nonreentrant%") or
    mod.getValue().toLowerCase().matches("%lock%")
  )
}

/**
 * Holds if a function modifies state.
 */
predicate modifiesState(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode node |
    node.getParent+() = func.getBody() |
    node instanceof Solidity::AssignmentExpression or
    node instanceof Solidity::AugmentedAssignmentExpression or
    node instanceof Solidity::UpdateExpression or
    node instanceof Solidity::UnaryExpression
  )
}

/**
 * External function suitable for invariant testing
 *
 * Output: invariant_target|contract|function|state_vars|access_level|risk_flags|file:line
 */
string formatInvariantTarget(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string riskFlags |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    (
      if hasAccessControl(func) then riskFlags = "auth" else riskFlags = "no_auth"
    ) and
    if hasReentrancyGuard(func) then riskFlags = riskFlags + ",reentrancy_guard" else riskFlags = riskFlags + ",no_guard"
    and
    result =
      "invariant_target|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + getFunctionVisibility(func) + "|" + riskFlags +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * View function that reads state (potential invariant source)
 *
 * Output: invariant_source|contract|function|visibility|file:line
 */
string formatInvariantSource(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public", "view"] and
    exists(Solidity::Identifier id |
      id.getParent+() = func.getBody() and
      exists(Solidity::StateVariableDeclaration sv |
        sv.getParent+() = contract and
        sv.getName().(Solidity::AstNode).getValue() = id.getValue()
      )
    ) and
    result =
      "invariant_source|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * External call without reentrancy guard (high priority for invariant testing)
 *
 * Output: high_risk_invariant|contract|function|has_external_call|has_guard|file:line
 */
string formatHighRiskInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string hasGuard |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    exists(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      isExternalCall(call)
    ) and
    not hasReentrancyGuard(func) and
    hasGuard = "false" and
    result =
      "high_risk_invariant|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|external_call|" + hasGuard +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Balance-modifying function (key for financial invariants)
 *
 * Output: balance_invariant|contract|function|operation_type|file:line
 */
string formatBalanceInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string opType |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      // Looks like a balance-modifying function
      (
        getFunctionName(func).toLowerCase().matches("%transfer%") or
        getFunctionName(func).toLowerCase().matches("%withdraw%") or
        getFunctionName(func).toLowerCase().matches("%deposit%") or
        getFunctionName(func).toLowerCase().matches("%mint%") or
        getFunctionName(func).toLowerCase().matches("%burn%") or
        getFunctionName(func).toLowerCase().matches("%send%") or
        getFunctionName(func).toLowerCase().matches("%pay%")
      ) and
      opType = "token_transfer"
    ) and
    result =
      "balance_invariant|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + opType +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Permission-modifying function (key for access control invariants)
 *
 * Output: permission_invariant|contract|function|access_level|file:line
 */
string formatPermissionInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      getFunctionName(func).toLowerCase().matches("%grant%") or
      getFunctionName(func).toLowerCase().matches("%revoke%") or
      getFunctionName(func).toLowerCase().matches("%setowner%") or
      getFunctionName(func).toLowerCase().matches("%addadmin%") or
      getFunctionName(func).toLowerCase().matches("%removeadmin%") or
      getFunctionName(func).toLowerCase().matches("%pause%") or
      getFunctionName(func).toLowerCase().matches("%unpause%")
    ) and
    result =
      "permission_invariant|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Function with require/assert validations (potential invariant expressions)
 *
 * Output: validation_invariant|contract|function|validation_count|file:line
 */
string formatValidationInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, int validationCount |
    func.getParent+() = contract and
    validationCount = count(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      (
        call.getFunction().(Solidity::Identifier).getValue() = "require" or
        call.getFunction().(Solidity::Identifier).getValue() = "assert" or
        call.getFunction().(Solidity::Identifier).getValue() = "revert"
      )
    ) and
    validationCount > 0 and
    result =
      "validation_invariant|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + validationCount.toString() +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * State machine transition function (key for state invariant testing)
 *
 * Output: state_machine_invariant|contract|function|transitions_from|file:line
 */
string formatStateMachineInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      getFunctionName(func).toLowerCase().matches("%setstate%") or
      getFunctionName(func).toLowerCase().matches("%transition%") or
      getFunctionName(func).toLowerCase().matches("%next%") or
      getFunctionName(func).toLowerCase().matches("%advance%") or
      getFunctionName(func).toLowerCase().matches("%change%state%")
    ) and
    result =
      "state_machine_invariant|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + getFunctionVisibility(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatInvariantTarget(_)
  or
  info = formatInvariantSource(_)
  or
  info = formatHighRiskInvariant(_)
  or
  info = formatBalanceInvariant(_)
  or
  info = formatPermissionInvariant(_)
  or
  info = formatValidationInvariant(_)
  or
  info = formatStateMachineInvariant(_)
select info, info
