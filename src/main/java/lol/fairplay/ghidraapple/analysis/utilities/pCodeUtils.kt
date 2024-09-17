package lol.fairplay.ghidraapple.analysis.utilities

import ghidra.program.database.symbol.ClassSymbol
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.ReferenceManager
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.Msg
import java.util.*

fun getConstantFromVarNode(varnode: Varnode): Optional<Address> {

    return when {
        varnode.isRegister && varnode.def != null -> getConstantFromPcodeOp(varnode.def)
        varnode.isConstant -> Optional.of(varnode.address)
        varnode.isAddress -> Optional.of(varnode.address)
        varnode.isUnique -> getConstantFromPcodeOp(varnode.def)
        else -> Optional.empty()
    }
}

fun getConstantFromPcodeOp(pcodeOp: PcodeOp): Optional<Address> {
    when (pcodeOp.opcode) {
        PcodeOp.CAST -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.COPY -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.PTRSUB -> {
            val ptrSubInput = pcodeOp.inputs.first { !(it.isConstant && it.offset == 0L)}
            return getConstantFromVarNode(ptrSubInput)
        }
        PcodeOp.LOAD -> return Optional.empty()
        // Multiequal is a phi node, so we can't get _one_ constant from it
        PcodeOp.MULTIEQUAL -> return Optional.empty<Address>()
        PcodeOp.INDIRECT -> return getConstantFromVarNode(pcodeOp.inputs[0])
        PcodeOp.CALL -> return Optional.empty()
        else -> {
            Msg.error("getConstantFromPcodeOp",
                "Unknown opcode ${pcodeOp.mnemonic} encountered at ${pcodeOp.seqnum.target}")
            return Optional.empty()
        }


    }

}
/**
 * Helper method to convert any kind of address into the same address in the default
 * address space
 * This is useful because constants in the decompiler will be represented as 'addresses'
 * in the 'const' address space, and they need to be converted to the default address space
 * before they can be used in the program API
 */
fun Address.toDefaultAddressSpace(program: Program): Address {
    return program.addressFactory.defaultAddressSpace.getAddress(this.offset)
}

fun Function.hasTag(tag: String): Boolean {
    return this.tags.any { it.name == tag }
}

fun ReferenceManager.setCallTarget(callsite: Address, targetFunction: Function, sourceType: SourceType) {
    val ref = addMemoryReference(
        callsite,
        targetFunction.entryPoint,
        ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL,
        sourceType, 0)
    setPrimary(ref, true)
}


/**
 * Takes a symbol like `_OBJC_CLASS_$_CLCircularRegion` and returns the DataType for that class.
 */
fun getDataTypeFromSymbol(symbol: Symbol): DataType {
    val className = symbol.name.removePrefix("_OBJC_CLASS_\$_")
    val type = symbol.program.dataTypeManager.getDataType("/GA_OBJC/$className")
    return type
}

fun getDataTypeFromClassSymbol(symbol: ClassSymbol): DataType {
    val className = symbol.name.removePrefix("_OBJC_CLASS_\$_")
    val type = symbol.program.dataTypeManager.getDataType("/GA_OBJC/$className")
    return type
}

fun getClassSymbolForAddress(program: Program, address: Address): ClassSymbol? {
    val symbol = program.symbolTable.getSymbols(address).filter {  it.name.startsWith("_OBJC_CLASS_\$")}.single()
    return getClassSymbolFromCodeSymbol(symbol)
}

fun getClassSymbolFromCodeSymbol(symbol: Symbol): ClassSymbol? {
    val className = symbol.name.removePrefix("_OBJC_CLASS_\$_")

    val clsSymbol = symbol.program.symbolTable.getSymbols(className).filterIsInstance<ClassSymbol>().singleOrNull()
    return clsSymbol
}
