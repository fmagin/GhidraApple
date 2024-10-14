package lol.fairplay.ghidraapple;

import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.actions.ChooseMsgSendCalleeAction;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import lol.fairplay.ghidraapple.comands.InlineTrivialAccessors;



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
        new ActionBuilder("Inline all trivial accessors", "GhidraApple")
                .description("Inline all trivial accessors")
                .enabled(true)
                .menuPath("Objective-C", "Inline all trivial accessors")
                .onAction(e -> {
                    new InlineTrivialAccessors(true).applyTo(currentProgram);
                })
                .buildAndInstall(tool);
        new ActionBuilder("Outline all trivial accessors", "GhidraApple")
                .description("Inline all trivial accessors")
                .enabled(true)
                .menuPath("Objective-C", "Outline all trivial accessors")
                .onAction(e -> {
                    new InlineTrivialAccessors(false).applyTo(currentProgram);
                })
                .buildAndInstall(tool);
    }

}
