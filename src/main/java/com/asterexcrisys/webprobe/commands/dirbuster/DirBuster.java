package com.asterexcrisys.webprobe.commands.dirbuster;

import com.asterexcrisys.webprobe.constants.DirBusterConstants;
import picocli.CommandLine.Command;
import java.util.concurrent.Callable;

@Command(name = "dirbuster", mixinStandardHelpOptions = true, version = DirBusterConstants.VERSION, description = DirBusterConstants.DESCRIPTION)
public class DirBuster implements Callable<String> {

    @Override
    public String call() throws Exception {
        throw new UnsupportedOperationException("not supported yet");
    }

}