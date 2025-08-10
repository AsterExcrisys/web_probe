package com.asterexcrisys.webprobe.commands.whois;

import com.asterexcrisys.webprobe.commands.whois.subcommands.Standard;
import com.asterexcrisys.webprobe.commands.whois.subcommands.Secure;
import com.asterexcrisys.webprobe.constants.WhoIsConstants;
import picocli.CommandLine.Command;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(
        name = "whois", mixinStandardHelpOptions = true, version = WhoIsConstants.VERSION, description = WhoIsConstants.DESCRIPTION,
        subcommands = {Standard.class, Secure.class}
)
public class WhoIs implements Callable<String> {

    @Override
    public String call() throws Exception {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : WhoIsConstants.SUBCOMMANDS.entrySet()) {
            builder.append("%s: %s".formatted(entry.getKey(), entry.getValue()));
            builder.append(System.lineSeparator());
        }
        return builder.toString();
    }

}