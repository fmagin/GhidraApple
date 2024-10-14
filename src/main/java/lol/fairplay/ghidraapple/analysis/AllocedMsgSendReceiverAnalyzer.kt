package lol.fairplay.ghidraapple.analysis


import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objcclasses.OCTypeInjectorAnalyzer
import lol.fairplay.ghidraapple.analysis.utilities.getClassSymbolForAddress
import lol.fairplay.ghidraapple.analysis.utilities.getConstantFromVarNode
import lol.fairplay.ghidraapple.analysis.utilities.toDefaultAddressSpace
import kotlin.jvm.optionals.getOrNull

/**
 * This analyzer follows the intra-procedural backwards slice to find the allocation site of the object
 * It uses the definition chain from the P-Code information, and as such does not account for memory loads/stores
 */
class AllocedMsgSendReceiverAnalyzer: AbstractDynamicDispatchAnalyzer<MsgSendCallInfo>("Alloced Receiver Analyzer", "foo", AnalyzerType.FUNCTION_ANALYZER) {

    init {
        priority = OCTypeInjectorAnalyzer.PRIORITY.after()
        setSupportsOneTimeAnalysis()
    }
    override fun processDispatchSite(highFunction: HighFunction, pcodeOp: PcodeOp): Result<MsgSendCallInfo> {

        val selector = getSelectorFromPcodeOp(highFunction, pcodeOp)
        if (selector == null) {
            Msg.error(this, "No selector found for ${pcodeOp.seqnum.target}")
            return Result.failure(Exception("No selector found for ${pcodeOp.seqnum.target}"))
        }

        // Run backwards until we find the call op that created this receiver object
        val allocSite = findAllocForVarnode(pcodeOp.inputs[1])
        if (allocSite == null) {
            Msg.error(this, "No allocation site found for ${pcodeOp.inputs[1]}")
            return Result.failure(Exception("No allocation site found for ${pcodeOp.inputs[1]}"))
        }
        val clsReference = getConstantFromVarNode(allocSite.inputs[1]).getOrNull()
        if (clsReference == null) {
            Msg.error(this, "Couldn't find class reference for alloc call at ${allocSite.seqnum.target}")
            return Result.failure(Exception("Couldn't find class reference for alloc call at ${allocSite.seqnum.target}"))
        }


        val cls = getClassSymbolForAddress(highFunction.function.program,  clsReference.toDefaultAddressSpace(highFunction.function.program))


        if (cls != null) {
            val implementation = getImplementationForTuple(
                highFunction.function.program,
                cls,
                selector
            )


            return Result.success(MsgSendCallInfo(pcodeOp.seqnum.target, cls, selector, implementation))
        }
        return Result.failure(Exception("No alloc found"))
    }

    private fun findAllocForVarnode(node: Varnode): PcodeOp? {
        when (node.def?.opcode) {
            PcodeOp.CAST -> return findAllocForVarnode(node.def.inputs[0])
//            PcodeOp.COPY -> return findAllocForVarnode(node.def.inputs[0])
            PcodeOp.CALL -> return node.def
            null -> return null
            else -> {
                Msg.error(this, "Unexpected opcode ${node.def.mnemonic} encountered at ${node.def.seqnum.target}")
                return null
            }
        }
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
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
}