package com.asterexcrisys.webprobe.commands.curl;

import com.asterexcrisys.webprobe.commands.curl.subcommands.*;
import com.asterexcrisys.webprobe.constants.CUrlConstants;
import picocli.CommandLine.Command;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(
        name = "curl", mixinStandardHelpOptions = true, version = CUrlConstants.VERSION, description = CUrlConstants.DESCRIPTION,
        subcommands = {Get.class, Post.class, Put.class, Patch.class, Delete.class, Head.class, Options.class, Trace.class}
)
public class CUrl implements Callable<String> {

    @Override
    public String call() {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : CUrlConstants.SUBCOMMANDS.entrySet()) {
            builder.append("%s: %s".formatted(entry.getKey(), entry.getValue()));
            builder.append(System.lineSeparator());
        }
        return builder.toString();
    }

}