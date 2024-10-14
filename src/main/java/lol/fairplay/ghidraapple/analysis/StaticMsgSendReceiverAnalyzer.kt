package lol.fairplay.ghidraapple.analysis

import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.utilities.getClassSymbolForAddress
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import kotlin.jvm.optionals.getOrNull





/**
 * This analyzer handles all static calls, i.e. msgSend or stub calls where the receiver is a static class
 * and then links the callsite to the implementation.
 * For internal classes these implementations should be part of the binary
 * TODO: For external classes it will create a new function in the external segment, and link to that
 */
class StaticMsgSendReceiverAnalyzer: AbstractDynamicDispatchAnalyzer<MsgSendCallInfo>(
    NAME,
    "Checks all msgSend calls for a static receiver and links to the target implementation",
    AnalyzerType.FUNCTION_ANALYZER) {

    companion object {
        const val NAME = "StaticMsgSendReceiverAnalyzer"
    }

    init {
        // Should run before type propagation, because the resulting information will provide more type info
        // but this analysis doesn't _need_ type info
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before())
        setSupportsOneTimeAnalysis()
    }

    

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        // Get the msgSend function and make sure that it has a correct signature set up
        setupMsgSendSignature(program)

        val results = doDispatchAnalysis(program, set, monitor, log)
        results.mapNotNull { it.getOrNull() }.forEach {
            Msg.info(this, it.toString())
            if (it.implementation != null){
                it.applyToProgram(program)
            }
        }
        return true
    }

    override fun processDispatchSite(highFunction: HighFunction, pcodeOp: PcodeOp): Result<MsgSendCallInfo> {
        // Check if we have a constant receiver
        val receiver = getConstantFromVarNode(pcodeOp.inputs[1]).getOrNull().let {
            it?.toDefaultAddressSpace(highFunction.function.program)
                ?.let { addr -> getClassSymbolForAddress(highFunction.function.program, addr) }
//                ?.let { classSymbol -> return Result.success(StaticCallInfo(pcodeOp.seqnum.target, classSymbol, null, null)) }
        }
        val selector = getSelectorFromPcodeOp(highFunction, pcodeOp)
        if (receiver != null) {
            val implementation = selector?.let {
                getImplementationForTuple(
                    highFunction.function.program,
                    receiver,
                    it
                )
            }


            return Result.success(MsgSendCallInfo(pcodeOp.seqnum.target, receiver, selector, implementation))
        }
        return Result.failure(Exception("No static receiver found"))
    }
}