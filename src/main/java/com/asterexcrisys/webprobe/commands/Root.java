package com.asterexcrisys.webprobe.commands;

import com.asterexcrisys.webprobe.commands.curl.CUrl;
import com.asterexcrisys.webprobe.commands.dig.Dig;
import com.asterexcrisys.webprobe.commands.dirbuster.DirBuster;
import com.asterexcrisys.webprobe.commands.nmap.NMap;
import com.asterexcrisys.webprobe.commands.whois.WhoIs;
import com.asterexcrisys.webprobe.constants.RootConstants;
import picocli.CommandLine.Command;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(
        name = "root", mixinStandardHelpOptions = true, version = RootConstants.VERSION, description = RootConstants.DESCRIPTION,
        subcommands = {CUrl.class, Dig.class, WhoIs.class, DirBuster.class, NMap.class}
)
public class Root implements Callable<String> {

    @Override
    public String call() {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : RootConstants.COMMANDS.entrySet()) {
            builder.append("%s: %s".formatted(entry.getKey(), entry.getValue()));
            builder.append(System.lineSeparator());
        }
        return builder.toString();
    }

}