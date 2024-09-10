package lol.fairplay.ghidraapple;

import docking.action.builder.ActionBuilder;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.ChooseMsgSendCalleeAction;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.PcodeOp;
import lol.fairplay.ghidraapple.actions.ChooseMsgSendCalleeDialog;

import static lol.fairplay.ghidraapple.analysis.PCodeUtilsKt.getFunctionForPCodeCall;
import static lol.fairplay.ghidraapple.analysis.selectortrampoline.SelectorTrampolineAnalyzer.TRAMPOLINE_TAG;


//@formatter:off
@PluginInfo(
        status=PluginStatus.STABLE,
        packageName=GhidraApplePluginPackage.PKG_NAME,
        category=PluginCategoryNames.COMMON,
        shortDescription="",
        description=""
)
//@formatter:on
public class GhidraApplePlugin extends ProgramPlugin {
    public GhidraApplePlugin(PluginTool plugintool) {
        super(plugintool);
        setupActions();
    }

    private void setupActions() {
        tool.addAction(new ChooseMsgSendCalleeAction());
    }

}
