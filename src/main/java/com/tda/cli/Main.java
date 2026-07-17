package com.tda.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "tda",
        mixinStandardHelpOptions = true,
        version = "tda " + com.tda.core.AnalysisEngine.VERSION,
        description = "Enterprise Java thread dump analyzer - fully offline.",
        subcommands = {AnalyzeCommand.class})
public final class Main implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    public static void main(String[] args) {
        int code = new CommandLine(new Main()).execute(args);
        System.exit(code);
    }
}
