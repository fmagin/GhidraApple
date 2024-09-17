package lol.fairplay.ghidraapple.analysis

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileException
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.symbol.ClassSymbol
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.selectortrampoline.SelectorTrampolineAnalyzer
import lol.fairplay.ghidraapple.analysis.utilities.hasTag
import lol.fairplay.ghidraapple.analysis.utilities.setCallTarget

abstract class AbstractDynamicDispatchAnalyzer<T>(name: String, s: String, analyzerType: AnalyzerType):
    AbstractAnalyzer(name, s, analyzerType) {
    /**
     * Collect all FunctionSymbols for functions that are effectively dynamic dispatch callsites.
     * This includes: msgSend and all trampoline functions
     *
     * It does not include sendSuper, because the first argument isn't the receiver, but pointer to a struct with
     * the receiver, and the super class
     */
    protected fun getDynamicDispatchFunctions(program: Program): Collection<Function> {
        // start with just msgSend for now
        val result = mutableListOf<Function>()
        val msgSendFunctions = listOf(
            "_objc_msgSend",
        )
        msgSendFunctions.forEach { name ->
            program.symbolTable.getSymbols(name).mapNotNull { it.`object` as? Function }.forEach { result.add(it) }
        }

        program.functionManager.getFunctions(true)
            .filter {
                func -> func.hasTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)
            }.forEach { result.add(it) }

        Msg.info(this, "Found ${result.size} dynamic dispatch functions")

        return result
    }

    override fun canAnalyze(program: Program): Boolean {
        // TODO: Check that the program is an Objective-C program, and has a `msgSend` function
        return super.canAnalyze(program)
    }


    open fun createDecompiler(program: Program): DecompInterface{
        val decompiler = DecompInterface()
        decompiler.openProgram(program)
        decompiler.simplificationStyle = "decompile"
        decompiler.toggleSyntaxTree(true)
        decompiler.options = DecompileOptions().apply {
            isRespectReadOnly = true
        }
        return decompiler
    }

    fun doDispatchAnalysis(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Collection<Result<T>> {

        val decompiler = createDecompiler(program)

        val sites = getDynamicDispatchSites(program, set)
        Msg.info(this, "Analyzing ${sites.size} dynamic dispatch sites")
        val results: List<Result<T>> = sites.map { (function, addresses) ->

            val decompileResults = decompiler.decompileFunction(function, 30, monitor)
            if (decompileResults == null || decompileResults.highFunction == null) {
                Msg.error(this, "Failed to decompile function ${function.name}")
                throw DecompileException("", "Failed to decompile function ${function.name}")
            }
            decompileResults.highFunction.pcodeOps.asSequence()
                .filter {
                    it.opcode == PcodeOp.CALL && it.seqnum.target in addresses
                }
                .map {
                    processDispatchSite(decompileResults.highFunction, it)
                }.toList()
        }.flatten()
        decompiler.dispose()

        return results
    }


    /**
     * Get all dynamic dispatch sites in the program, grouped by the function they are contained in
     */
    protected fun getDynamicDispatchSites(program: Program, set: AddressSetView?): Map<Function, List<Address>> {
        return getDynamicDispatchFunctions(program).map {
            func -> program.referenceManager.getReferencesTo(func.entryPoint)
            .filter { set == null || it.fromAddress in set }
            .filter { it.referenceType.isCall }
            .map { it.fromAddress to program.functionManager.getFunctionContaining(it.fromAddress) }
            .filter { (_, func) -> func != null }
            // We don't want to analyze trampoline functions, because they will never have useful info
            .filter { (_, caller) -> ! caller.hasTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)}
        }
            .flatten()
            .groupBy({ it.second }, { it.first })

    }

    abstract fun processDispatchSite(highFunction: HighFunction, pcodeOp: PcodeOp): Result<T>

    /**
     * Traces a Varnode back to find the call that initially allocated it
     *
     * We need this because if we can find an alloc call that created some receiver then we can be sure that it is
     * of the type that Ghidra infers it to be (i.e. exactly the type allocated) and don't have to worry about
     * technically possible subtypes
     *
     */
    fun searchVarnodeAlloc(varnode: Varnode): Boolean {
        TODO()
    }

    protected fun getSelectorFromPcodeOp(highFunction: HighFunction, pcodeOp: PcodeOp): Selector? {
        assert(pcodeOp.opcode == PcodeOp.CALL)
        // Get function being called
        val target = pcodeOp.inputs[0]
        val targetFunction = highFunction.function.program.functionManager.getFunctionAt(target.address)
        if (targetFunction == null) {
            Msg.error(this, "Couldn't find function at ${target.address}")
            return null
        }
        if (targetFunction.hasTag(SelectorTrampolineAnalyzer.TRAMPOLINE_TAG)) {
            return targetFunction.name
        }
        return null
    }

    protected fun getImplementationForTuple(program: Program, classSymbol: ClassSymbol, selector: Selector): Function? {
        program.symbolTable.getSymbols(classSymbol.`object` as GhidraClass).forEach {
            if (it.name == selector) {
                return it.`object` as Function
            }
        }
        return null
    }

}
