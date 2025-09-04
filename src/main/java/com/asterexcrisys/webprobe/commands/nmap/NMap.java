package com.asterexcrisys.webprobe.commands.nmap;

import com.asterexcrisys.webprobe.commands.nmap.subcommands.Host;
import com.asterexcrisys.webprobe.commands.nmap.subcommands.Port;
import com.asterexcrisys.webprobe.constants.NMapConstants;
import picocli.CommandLine.Command;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(
        name = "nmap", mixinStandardHelpOptions = true, version = NMapConstants.VERSION, description = NMapConstants.DESCRIPTION,
        subcommands = {Port.class, Host.class}
)
public class NMap implements Callable<String> {

    @Override
    public String call() throws Exception {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : NMapConstants.SUBCOMMANDS.entrySet()) {
            builder.append("%s: %s".formatted(entry.getKey(), entry.getValue()));
            builder.append(System.lineSeparator());
        }
        return builder.toString();
    }

}