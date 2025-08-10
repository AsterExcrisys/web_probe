package com.asterexcrisys.webprobe.commands.dig;

import com.asterexcrisys.webprobe.commands.dig.subcommands.Address;
import com.asterexcrisys.webprobe.commands.dig.subcommands.Domain;
import com.asterexcrisys.webprobe.constants.DigConstants;
import picocli.CommandLine.Command;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(
        name = "dig", mixinStandardHelpOptions = true, version = DigConstants.VERSION, description = DigConstants.DESCRIPTION,
        subcommands = {Domain.class, Address.class}
)
public class Dig implements Callable<String> {

    @Override
    public String call() throws Exception {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : DigConstants.SUBCOMMANDS.entrySet()) {
            builder.append("%s: %s".formatted(entry.getKey(), entry.getValue()));
            builder.append(System.lineSeparator());
        }
        return builder.toString();
    }

}