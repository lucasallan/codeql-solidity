/**
 * @name Reentrancy pattern analysis
 * @description Detects CEI violations using control flow reachability instead of line numbers.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/reentrancy-patterns
 * @tags analysis
 *       reentrancy
 *       security
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.callgraph.CallResolution
import codeql.solidity.controlflow.internal.ControlFlowGraphImpl

/** Gets the contract name. */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Holds if a function has a reentrancy guard modifier. */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent() = func and
    (
      mod.getValue().toLowerCase().matches("%nonreentrant%") or
      mod.getValue().toLowerCase().matches("%lock%") or
      mod.getValue().toLowerCase().matches("%mutex%") or
      mod.getValue().toLowerCase().matches("%guard%")
    )
  )
}

/**
 * Holds if `id` refers to a state variable `varName` declared in `contract`.
 */
private predicate isStateVarIdentifier(
  Solidity::Identifier id,
  Solidity::ContractDeclaration contract,
  string varName
) {
  exists(Solidity::StateVariableDeclaration sv |
    sv.getParent+() = contract and
    varName = sv.getName().(Solidity::AstNode).getValue() and
    id.getValue() = varName
  )
}

/**
 * Holds if `node` directly modifies a state variable declared in `contract`.
 *
 * Covers: assignment, augmented assignment (+=, -=), update (++, --),
 * delete, and array push/pop.
 */
predicate directlyModifiesState(
  Solidity::AstNode node,
  Solidity::ContractDeclaration contract,
  string varName
) {
  exists(Solidity::Identifier id |
    isStateVarIdentifier(id, contract, varName) and
    (
      // Assignment (x = ...) or augmented assignment (x += ...)
      node.(Solidity::AssignmentExpression).getLeft() = id.getParent+()
      or
      node.(Solidity::AugmentedAssignmentExpression).getLeft() = id.getParent+()
      or
      // Update expression (x++, x--, ++x, --x)
      id = node.(Solidity::UpdateExpression).getArgument().getAChild*()
      or
      // Delete expression (delete x)
      exists(Solidity::UnaryExpression unary |
        node = unary and
        unary.getOperator().(Solidity::AstNode).getValue() = "delete" and
        id = unary.getArgument().getAChild*()
      )
      or
      // Array push/pop (arr.push(...), arr.pop())
      exists(Solidity::MemberExpression mem |
        node.(Solidity::CallExpression).getFunction() = mem and
        mem.getProperty().(Solidity::AstNode).getValue() in ["push", "pop"] and
        id = mem.getObject().getAChild*()
      )
    )
  )
}

/**
 * Holds if `call` is an internal function call (not external).
 */
private predicate isInternalCall(Solidity::CallExpression call) {
  CallResolution::resolveCall(call, _) and
  not ExternalCalls::isLowLevelCall(call) and
  not ExternalCalls::isContractReferenceCall(call) and
  not ExternalCalls::isEtherTransfer(call) and
  not ExternalCalls::isThisCall(call)
}

/**
 * Holds if `func` (or any function it transitively calls internally)
 * modifies a state variable in `contract`.
 *
 * Uses QL fixpoint: base case is direct modification, recursive case
 * follows internal call edges via CallResolution.
 */
predicate functionModifiesState(
  Solidity::FunctionDefinition func,
  Solidity::ContractDeclaration contract,
  string varName
) {
  // Base: func directly contains a state-modifying node
  exists(Solidity::AstNode mod |
    mod.getParent+() = func and
    directlyModifiesState(mod, contract, varName)
  )
  or
  // Recursive: func calls an internal function that modifies state
  exists(Solidity::CallExpression internalCall, Solidity::FunctionDefinition callee |
    internalCall.getParent+() = func and
    isInternalCall(internalCall) and
    CallResolution::resolveCall(internalCall, callee) and
    functionModifiesState(callee, contract, varName)
  )
}

/**
 * Holds if `stateModNode` is reachable from `callNode` via one or more CFG successor edges.
 * Uses CodeQL's built-in transitive closure which handles cycles (loops) correctly
 * and benefits from the evaluator's optimized fixpoint computation.
 */
predicate callReachesStateMod(CfgNode callNode, CfgNode stateModNode) {
  successor+(callNode, stateModNode)
}

/**
 * Holds if `call` is an external call (low-level, contract reference, or ether transfer).
 */
private predicate isExternalCall(Solidity::CallExpression call) {
  ExternalCalls::isLowLevelCall(call) or
  ExternalCalls::isContractReferenceCall(call) or
  ExternalCalls::isEtherTransfer(call)
}

/**
 * CEI violation: external call with a state modification reachable via CFG.
 *
 * Case 1 (direct): state-modifying node in same function, reachable via CFG successor+.
 * Case 2 (interprocedural): internal call reachable after external call, where
 *   the callee (transitively) modifies state.
 */
string formatCEIViolation(Solidity::CallExpression call) {
  isExternalCall(call) and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    call.getParent+() = func and
    func.getParent+() = contract and
    not hasReentrancyGuard(func) and
    (
      // Case 1: Direct state modification reachable from external call
      exists(Solidity::AstNode mod, string varName |
        mod.getParent+() = func and
        directlyModifiesState(mod, contract, varName) and
        callReachesStateMod(call, mod) and
        result =
          "{\"type\":\"cei_violation\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"callLine\":\"" +
            call.getLocation().getStartLine().toString() + "\",\"modLine\":\"" +
            mod.getLocation().getStartLine().toString() + "\",\"variable\":\"" + varName + "\"}"
      )
      or
      // Case 2: Internal call after external call, callee modifies state
      exists(Solidity::CallExpression internalCall, Solidity::FunctionDefinition callee, string varName |
        internalCall.getParent+() = func and
        isInternalCall(internalCall) and
        CallResolution::resolveCall(internalCall, callee) and
        callReachesStateMod(call, internalCall) and
        functionModifiesState(callee, contract, varName) and
        result =
          "{\"type\":\"cei_violation\",\"subtype\":\"interprocedural\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" +
            getFunctionName(func) + "\",\"callLine\":\"" + call.getLocation().getStartLine().toString() + "\",\"internalCallLine\":\"" +
            internalCall.getLocation().getStartLine().toString() + "\",\"callee\":\"" + getFunctionName(callee) + "\",\"variable\":\"" + varName + "\"}"
      )
    )
  )
}

/**
 * External call detection.
 */
string formatExternalCall(Solidity::CallExpression call) {
  isExternalCall(call) and
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string callType,
    string hasGuard
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    (
      ExternalCalls::isDelegateCall(call) and callType = "delegatecall"
      or
      ExternalCalls::isCall(call) and callType = "call"
      or
      ExternalCalls::isStaticCall(call) and callType = "staticcall"
      or
      ExternalCalls::isEtherTransfer(call) and callType = "transfer"
      or
      ExternalCalls::isContractReferenceCall(call) and
      not ExternalCalls::isLowLevelCall(call) and
      not ExternalCalls::isEtherTransfer(call) and
      callType = "high_level"
    ) and
    (
      if hasReentrancyGuard(func) then hasGuard = "true" else hasGuard = "false"
    ) and
    result =
      "{\"type\":\"external_call\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"callType\":\"" + callType +
        "\",\"hasGuard\":\"" + hasGuard + "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * State modification detection (all mutation types).
 */
string formatStateMod(Solidity::AstNode mod) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string varName
  |
    mod.getParent+() = func and
    func.getParent+() = contract and
    directlyModifiesState(mod, contract, varName) and
    result =
      "{\"type\":\"state_mod\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"variable\":\"" + varName + "\",\"line\":\"" +
        mod.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Unguarded function with external calls and state modifications.
 */
string formatUnguardedFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, int extCalls, int stateMods |
    func.getParent+() = contract and
    not hasReentrancyGuard(func) and
    extCalls = count(Solidity::CallExpression call | call.getParent+() = func and isExternalCall(call)) and
    stateMods = count(Solidity::AstNode mod | mod.getParent+() = func and directlyModifiesState(mod, contract, _)) and
    extCalls > 0 and
    stateMods > 0 and
    result =
      "{\"type\":\"unguarded_external\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"externalCalls\":\"" +
        extCalls.toString() + "\",\"stateMods\":\"" + stateMods.toString() + "\",\"location\":\"" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Callback function detection (common reentrancy targets).
 * Only flags external/public functions — private/internal callbacks are not entry points.
 */
string formatCallback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    // Only external/public functions are reentrancy entry points
    exists(Solidity::AstNode vis |
      vis = func.getAChild() and
      vis.toString() in ["external", "public"]
    ) and
    (
      funcName.toLowerCase().matches("%callback%") or
      funcName.toLowerCase().matches("%hook%") or
      funcName.toLowerCase().matches("%on%received%") or
      funcName.toLowerCase() = "tokensreceived" or
      funcName.toLowerCase() = "ontokentransfer" or
      funcName.toLowerCase() = "onerc721received" or
      funcName.toLowerCase() = "onerc1155received" or
      funcName.toLowerCase() = "uniswapv2call" or
      funcName.toLowerCase() = "uniswapv3swapcallback" or
      funcName.toLowerCase().matches("%flashloan%")
    ) and
    result =
      "{\"type\":\"callback\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + funcName + "\",\"location\":\"" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Receive/fallback function detection.
 */
string formatEthReceiver(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcType |
    func.getParent+() = contract and
    (
      getFunctionName(func) = "receive" and funcType = "receive"
      or
      getFunctionName(func) = "fallback" and funcType = "fallback"
    ) and
    result =
      "{\"type\":\"eth_receiver\",\"contract\":\"" + getContractName(contract) + "\",\"functionType\":\"" + funcType + "\",\"location\":\"" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatExternalCall(_)
  or
  info = formatStateMod(_)
  or
  info = formatCEIViolation(_)
  or
  info = formatUnguardedFunction(_)
  or
  info = formatCallback(_)
  or
  info = formatEthReceiver(_)
select info, info
