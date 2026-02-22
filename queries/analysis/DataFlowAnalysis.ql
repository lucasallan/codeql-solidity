/**
 * @name Data flow analysis
 * @description Analyzes data flow: taint sources, sinks, and propagation.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/data-flow-analysis
 * @tags analysis
 *       dataflow
 *       taint
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls

/**
 * Gets the contract name.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Taint source: msg.sender access.
 * Output: taint_source|contract|function|type|name|file:line
 */
string formatMsgSender(Solidity::MemberExpression expr) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    expr.getObject().(Solidity::Identifier).getValue() = "msg" and
    expr.getProperty().(Solidity::AstNode).getValue() = "sender" and
    result =
      "{\"type\":\"taint_source\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) +
        "\",\"sourceType\":\"msg_sender\",\"source\":\"msg.sender\",\"location\":\"" + expr.getLocation().getFile().getName() + ":" +
        expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint source: msg.value access.
 */
string formatMsgValue(Solidity::MemberExpression expr) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    expr.getObject().(Solidity::Identifier).getValue() = "msg" and
    expr.getProperty().(Solidity::AstNode).getValue() = "value" and
    result =
      "{\"type\":\"taint_source\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) +
        "\",\"sourceType\":\"msg_value\",\"source\":\"msg.value\",\"location\":\"" + expr.getLocation().getFile().getName() + ":" +
        expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint source: msg.data/calldata access.
 */
string formatMsgData(Solidity::MemberExpression expr) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    expr.getObject().(Solidity::Identifier).getValue() = "msg" and
    expr.getProperty().(Solidity::AstNode).getValue() = "data" and
    result =
      "{\"type\":\"taint_source\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) +
        "\",\"sourceType\":\"msg_data\",\"source\":\"msg.data\",\"location\":\"" + expr.getLocation().getFile().getName() + ":" +
        expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint source: block.timestamp access.
 */
string formatBlockTimestamp(Solidity::MemberExpression expr) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    expr.getObject().(Solidity::Identifier).getValue() = "block" and
    expr.getProperty().(Solidity::AstNode).getValue() = "timestamp" and
    result =
      "{\"type\":\"taint_source\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) +
        "\",\"sourceType\":\"block_timestamp\",\"source\":\"block.timestamp\",\"location\":\"" + expr.getLocation().getFile().getName() + ":" +
        expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint source: tx.origin access.
 */
string formatTxOrigin(Solidity::MemberExpression expr) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    expr.getParent+() = func and
    func.getParent+() = contract and
    expr.getObject().(Solidity::Identifier).getValue() = "tx" and
    expr.getProperty().(Solidity::AstNode).getValue() = "origin" and
    result =
      "{\"type\":\"taint_source\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) +
        "\",\"sourceType\":\"tx_origin\",\"source\":\"tx.origin\",\"location\":\"" + expr.getLocation().getFile().getName() + ":" +
        expr.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint source: function parameters (external/public).
 * Output: param_source|contract|function|param_name|param_type|file:line
 */
string formatParameter(Solidity::Parameter param) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string paramName,
    string visibility
  |
    param.getParent() = func and
    func.getParent+() = contract and
    paramName = param.getName().(Solidity::AstNode).getValue() and
    exists(Solidity::AstNode vis |
      vis.getParent() = func and
      vis.toString() = "Visibility" and
      visibility = vis.getAChild().getValue()
    ) and
    visibility in ["external", "public"] and
    result =
      "{\"type\":\"param_source\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"paramName\":\"" + paramName +
        "\",\"paramType\":\"" + param.getType().(Solidity::AstNode).toString() + "\",\"location\":\"" +
        param.getLocation().getFile().getName() + ":" +
        param.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint sink: external call.
 * Output: taint_sink|contract|function|sink_type|file:line
 */
string formatExternalCallSink(Solidity::CallExpression call) {
  (
    ExternalCalls::isLowLevelCall(call) or
    ExternalCalls::isContractReferenceCall(call)
  ) and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string sinkType |
    call.getParent+() = func and
    func.getParent+() = contract and
    (
      ExternalCalls::isDelegateCall(call) and sinkType = "delegatecall"
      or
      ExternalCalls::isCall(call) and sinkType = "external_call"
      or
      ExternalCalls::isStaticCall(call) and sinkType = "staticcall"
      or
      not ExternalCalls::isLowLevelCall(call) and sinkType = "high_level_call"
    ) and
    result =
      "{\"type\":\"taint_sink\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"sinkType\":\"" + sinkType +
        "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint sink: ether transfer.
 */
string formatEtherTransferSink(Solidity::CallExpression call) {
  ExternalCalls::isEtherTransfer(call) and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    call.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"taint_sink\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"sinkType\":\"ether_transfer\",\"location\":\"" +
        call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Taint sink: state variable write.
 */
string formatStateWriteSink(Solidity::AssignmentExpression assign) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::Identifier id, Solidity::StateVariableDeclaration sv
  |
    assign.getParent+() = func and
    func.getParent+() = contract and
    id.getParent+() = assign.getLeft() and
    sv.getParent+() = contract and
    sv.getName().(Solidity::AstNode).getValue() = id.getValue() and
    result =
      "{\"type\":\"taint_sink\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"sinkType\":\"state_write:" +
        id.getValue() + "\",\"location\":\"" + assign.getLocation().getFile().getName() + ":" +
        assign.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * State variable dependency: which functions read which state vars.
 * Output: state_read|contract|function|variable|file:line
 */
string formatStateRead(Solidity::Identifier id) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::StateVariableDeclaration sv
  |
    id.getParent+() = func.getBody() and
    func.getParent+() = contract and
    sv.getParent+() = contract and
    sv.getName().(Solidity::AstNode).getValue() = id.getValue() and
    // Not on left side of assignment
    not exists(Solidity::AssignmentExpression assign |
      id.getParent+() = assign.getLeft()
    ) and
    result =
      "{\"type\":\"state_read\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"variable\":\"" + id.getValue()
        + "\",\"location\":\"" + id.getLocation().getFile().getName() + ":" +
        id.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * State variable dependency: which functions write which state vars.
 * Output: state_write|contract|function|variable|file:line
 */
string formatStateWrite(Solidity::AssignmentExpression assign) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::Identifier id, Solidity::StateVariableDeclaration sv
  |
    assign.getParent+() = func and
    func.getParent+() = contract and
    id.getParent+() = assign.getLeft() and
    sv.getParent+() = contract and
    sv.getName().(Solidity::AstNode).getValue() = id.getValue() and
    result =
      "{\"type\":\"state_write\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"variable\":\"" + id.getValue()
        + "\",\"location\":\"" + assign.getLocation().getFile().getName() + ":" +
        assign.getLocation().getStartLine().toString() + "\"}"
  )
}


/**
 * Return statement (data flow out).
 * Output: return|contract|function|file:line
 */
string formatReturn(Solidity::ReturnStatement ret) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    ret.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"return\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"location\":\"" +
        ret.getLocation().getFile().getName() + ":" + ret.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Require/assert statements (validation points).
 * Output: validation|contract|function|type|file:line
 */
string formatValidation(Solidity::CallExpression call) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string valType |
    call.getParent+() = func and
    func.getParent+() = contract and
    (
      call.getFunction().(Solidity::Identifier).getValue() = "require" and valType = "require"
      or
      call.getFunction().(Solidity::Identifier).getValue() = "assert" and valType = "assert"
      or
      call.getFunction().(Solidity::Identifier).getValue() = "revert" and valType = "revert"
    ) and
    result =
      "{\"type\":\"validation\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"validationType\":\"" + valType + "\",\"location\":\"" +
        call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Conditional with taint source.
 * Output: conditional|contract|function|has_msg_sender|file:line
 */
string formatConditional(Solidity::IfStatement ifStmt) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string hasTaint |
    ifStmt.getParent+() = func and
    func.getParent+() = contract and
    (
      exists(Solidity::MemberExpression m |
        m.getParent+() = ifStmt.getCondition() and
        m.getObject().(Solidity::Identifier).getValue() = "msg" and
        m.getProperty().(Solidity::AstNode).getValue() = "sender"
      ) and
      hasTaint = "msg_sender"
      or
      not exists(Solidity::MemberExpression m |
        m.getParent+() = ifStmt.getCondition() and
        m.getObject().(Solidity::Identifier).getValue() = "msg"
      ) and
      hasTaint = "none"
    ) and
    result =
      "{\"type\":\"conditional\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"hasTaint\":\"" + hasTaint +
        "\",\"location\":\"" + ifStmt.getLocation().getFile().getName() + ":" +
        ifStmt.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatMsgSender(_)
  or
  info = formatMsgValue(_)
  or
  info = formatMsgData(_)
  or
  info = formatBlockTimestamp(_)
  or
  info = formatTxOrigin(_)
  or
  info = formatParameter(_)
  or
  info = formatExternalCallSink(_)
  or
  info = formatEtherTransferSink(_)
  or
  info = formatStateWriteSink(_)
  or
  info = formatStateRead(_)
  or
  info = formatStateWrite(_)
  or
  info = formatReturn(_)
  or
  info = formatValidation(_)
  or
  info = formatConditional(_)
select info, info
