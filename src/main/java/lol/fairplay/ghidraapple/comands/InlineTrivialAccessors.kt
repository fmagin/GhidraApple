package lol.fairplay.ghidraapple.comands

import ghidra.framework.cmd.Command
import ghidra.program.model.listing.Program
import lol.fairplay.ghidraapple.analysis.utilities.hasTag

/**
 * Inlines or outlines all functions marked as either TRIVIAL_SETTER or TRIVIAL_GETTER
 */
class InlineTrivialAccessors(val shouldInline: Boolean): Command<Program> {
    override fun applyTo(program: Program): Boolean {
        program.withTransaction<Exception>("Inline trivial accessors") {
            program.functionManager
                .getFunctions(true)
                .filter { it.hasTag("TRIVIAL_SETTER") || it.hasTag("TRIVIAL_GETTER") }
                .forEach {
                    it.isInline = shouldInline
                }
        }
        return true
    }

    override fun getStatusMsg(): String? {
        return null
    }

    override fun getName(): String {
        return "Inline all trivial accessors (getters and setters)"
    }
}