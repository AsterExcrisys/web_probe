package com.asterexcrisys.webprobe.commands.nmap;

import com.asterexcrisys.webprobe.commands.nmap.subcommands.Host;
import com.asterexcrisys.webprobe.commands.nmap.subcommands.Port;
import com.asterexcrisys.webprobe.constants.NMapConstants;
import picocli.CommandLine.Command;
import java.util.concurrent.Callable;

@Command(
        name = "nmap", mixinStandardHelpOptions = true, version = NMapConstants.VERSION, description = NMapConstants.DESCRIPTION,
        subcommands = {Port.class, Host.class}
)
public class NMap implements Callable<String> {

    @Override
    public String call() throws Exception {
        throw new UnsupportedOperationException("not supported yet");
    }

}