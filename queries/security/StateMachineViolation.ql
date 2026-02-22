/**
 * @name State machine violation detection
 * @description Identifies state machine patterns for automatic test generation with Echidna/Halmos
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/analysis/state-machine-violation
 * @tags analysis state-machine testing solidity
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
    mod.getValue().toLowerCase().matches("%onlyrole%")
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
 * Holds if a function contains a require statement.
 */
predicate hasRequire(Solidity::FunctionDefinition func) {
  exists(Solidity::CallExpression call |
    call.getParent+() = func.getBody() |
    call.getFunction().(Solidity::Identifier).getValue() = "require"
  )
}

/**
 * Holds if a function contains an assert statement.
 */
predicate hasAssert(Solidity::FunctionDefinition func) {
  exists(Solidity::CallExpression call |
    call.getParent+() = func.getBody() |
    call.getFunction().(Solidity::Identifier).getValue() = "assert"
  )
}

/**
 * Gets state variable names for a contract.
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
 * State variable used as state indicator (enum-like)
 *
 * Output: state_indicator|contract|variable|type|file:line
 */
string formatStateIndicator(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%state%") or
      varName.toLowerCase().matches("%status%") or
      varName.toLowerCase().matches("%phase%") or
      varName.toLowerCase().matches("%mode%") or
      varName.toLowerCase().matches("%step%")
    ) and
    result =
      "state_indicator|" + getContractName(contract) + "|" + varName +
        "|" + var.getType().(Solidity::AstNode).toString() +
        "|" + var.getLocation().getFile().getName() + ":" +
        var.getLocation().getStartLine().toString()
  )
}

/**
 * Function that validates state before transition
 *
 * Output: state_transition_guard|contract|function|valid_states|file:line
 */
string formatStateTransitionGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    hasRequire(func) and
    modifiesState(func) and
    result =
      "state_transition_guard|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|requires_check|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * State transition function (modifies state)
 *
 * Output: state_transition|contract|function|has_access_control|file:line
 */
string formatStateTransition(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string hasAccess |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    (
      if hasAccessControl(func) then hasAccess = "true" else hasAccess = "false"
    ) and
    result =
      "state_transition|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + hasAccess +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Function with state-dependent access control
 *
 * Output: state_dependent_access|contract|function|has_require|file:line
 */
string formatStateDependentAccess(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string hasReq |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    hasRequire(func) and
    modifiesState(func) and
    not hasAccessControl(func) and
    hasReq = "true" and
    result =
      "state_dependent_access|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + hasReq +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Multiple state variables that should maintain invariants
 *
 * Output: state_invariant_group|contract|variable_count|file:line
 */
string formatStateInvariantGroup(Solidity::ContractDeclaration contract) {
  exists(int varCount |
    varCount = count(Solidity::StateVariableDeclaration v |
      v.getParent+() = contract and
      (
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%state%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%status%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%balance%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%total%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%supply%")
      )
    ) and
    varCount > 1 and
    result =
      "state_invariant_group|" + getContractName(contract) + "|" + varCount.toString() +
        "|" + contract.getLocation().getFile().getName() + ":" +
        contract.getLocation().getStartLine().toString()
  )
}

/**
 * Potential state machine contract
 *
 * Output: state_machine_contract|contract|has_state_indicator|has_transitions|file:line
 */
string formatStateMachineContract(Solidity::ContractDeclaration contract) {
  exists(int stateIndicators, int transitions |
    stateIndicators = count(Solidity::StateVariableDeclaration v |
      v.getParent+() = contract and
      (
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%state%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%status%")
      )
    ) and
    transitions = count(Solidity::FunctionDefinition f |
      f.getParent+() = contract and
      modifiesState(f)
    ) and
    stateIndicators > 0 and
    transitions > 0 and
    result =
      "state_machine_contract|" + getContractName(contract) + "|" + stateIndicators.toString() +
        "|" + transitions.toString() +
        "|" + contract.getLocation().getFile().getName() + ":" +
        contract.getLocation().getStartLine().toString()
  )
}

/**
 * Unguarded state transition (potential vulnerability)
 *
 * Output: unguarded_state_transition|contract|function|file:line
 */
string formatUnguardedStateTransition(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    not hasAccessControl(func) and
    not hasRequire(func) and
    result =
      "unguarded_state_transition|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Function that should only be called in specific state
 *
 * Output: state_restricted|contract|function|expected_states|file:line
 */
string formatStateRestricted(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    hasRequire(func) and
    (
      getFunctionName(func).toLowerCase().matches("%when%") or
      getFunctionName(func).toLowerCase().matches("%if%") or
      getFunctionName(func).toLowerCase().matches("%only%") or
      getFunctionName(func).toLowerCase().matches("%require%")
    ) and
    result =
      "state_restricted|" + getContractName(contract) + "|" + getFunctionName(func) +
        "|check_require|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Pausable contract pattern
 *
 * Output: pausable_pattern|contract|has_pause|has_unpause|file:line
 */
string formatPausablePattern(Solidity::ContractDeclaration contract) {
  exists(int pauseFuncs, int unpauseFuncs |
    pauseFuncs = count(Solidity::FunctionDefinition f |
      f.getParent+() = contract and
      f.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%pause%")
    ) and
    unpauseFuncs = count(Solidity::FunctionDefinition f |
      f.getParent+() = contract and
      f.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%unpause%")
    ) and
    pauseFuncs > 0 and
    unpauseFuncs > 0 and
    result =
      "pausable_pattern|" + getContractName(contract) + "|" + pauseFuncs.toString() +
        "|" + unpauseFuncs.toString() +
        "|" + contract.getLocation().getFile().getName() + ":" +
        contract.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatStateIndicator(_)
  or
  info = formatStateTransitionGuard(_)
  or
  info = formatStateTransition(_)
  or
  info = formatStateDependentAccess(_)
  or
  info = formatStateInvariantGroup(_)
  or
  info = formatStateMachineContract(_)
  or
  info = formatUnguardedStateTransition(_)
  or
  info = formatStateRestricted(_)
  or
  info = formatPausablePattern(_)
select info, info
