package com.asterexcrisys.webprobe.commands.dig.subcommands;

import com.asterexcrisys.webprobe.constants.GlobalConstants;
import com.asterexcrisys.webprobe.types.DnsRecord;
import com.asterexcrisys.webprobe.utilities.DigUtility;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;
import java.util.Optional;
import java.util.concurrent.Callable;

@Command(name = "domain", description = "Makes a DNS lookup request to the specified name server (resolver).")
public class Domain implements Callable<String> {

    @Parameters(index = "0", description = "The domain name to resolve into an address.", arity = "1")
    private String domain;

    @Option(names = {"-t", "--type"}, description = "The record type to use for the request (optional).", defaultValue = "A")
    private String type;

    @Option(names = {"-r", "--resolvers"}, description = "The resolver(s) (name server(s)) to use for the request (optional).", defaultValue = "")
    private String resolvers;

    @Option(names = {"-p", "--port"}, description = "The port to use for the resolver(s) (optional).", defaultValue = "53")
    private int port;

    @Override
    public String call() throws Exception {
        DnsRecord record = DnsRecord.nameOf(type.trim());
        if (record == null) {
            throw new IllegalArgumentException("specified record type is not supported");
        }
        if (port < GlobalConstants.MINIMUM_VALID_PORT || port > GlobalConstants.MAXIMUM_VALID_PORT) {
            throw new IllegalArgumentException("port must be within the range [%s, %s]".formatted(GlobalConstants.MINIMUM_VALID_PORT, GlobalConstants.MAXIMUM_VALID_PORT));
        }
        Optional<Resolver[]> resolvers = DigUtility.parseResolvers(this.resolvers, port);
        if (resolvers.isEmpty()) {
            throw new IllegalArgumentException("resolvers were either incorrectly formatted or not recognized");
        }
        Lookup lookup = new Lookup(Name.fromString(domain), record.type(), DClass.IN);
        lookup.setResolver(new ExtendedResolver(resolvers.get()));
        lookup.run();
        if (lookup.getResult() == Lookup.SUCCESSFUL) {
            Record[] answers = lookup.getAnswers();
            StringBuilder builder = new StringBuilder();
            for (Record answer : answers) {
                builder.append(answer.toString());
                builder.append(System.lineSeparator());
            }
            return builder.toString();
        }
        return "Error: %s".formatted(lookup.getErrorString());
    }

}