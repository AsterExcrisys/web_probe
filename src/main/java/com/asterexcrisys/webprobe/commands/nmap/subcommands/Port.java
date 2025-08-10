package com.asterexcrisys.webprobe.commands.nmap.subcommands;

import picocli.CommandLine.Command;
import java.util.concurrent.Callable;

@Command(name = "port", description = "Scans an host for open, closed, and filtered ports.")
public class Port implements Callable<String> {

    @Override
    public String call() throws Exception {
        return "";
    }

}