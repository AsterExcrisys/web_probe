package com.asterexcrisys.webprobe.commands.whois.subcommands;

import com.asterexcrisys.webprobe.constants.WhoIsConstants;
import com.asterexcrisys.webprobe.utilities.WhoIsUtility;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Optional;
import java.util.concurrent.Callable;

@Command(name = "standard", description = "Makes a default WhoIs request (non-RDAP) for the specified domain or address.")
public class Standard implements Callable<String> {

    @Parameters(index = "0", description = "The domain name or address to use for the request.", arity = "1")
    private String target;

    @Option(names = {"-r", "--registry"}, description = "The registry to use for the request (optional).", defaultValue = "")
    private String registry;

    @Option(names = {"-p", "--port"}, description = "The port to use for the resolver (optional).", defaultValue = "43")
    private int port;

    @Option(names = {"-a", "--address"}, description = "The flag to signal whether the target is a domain or an address (optional).", defaultValue = "false")
    private boolean isAddress;

    @Option(names = {"-t", "--timeout"}, description = "The timeout for the request in seconds (optional).", defaultValue = "5000")
    private long timeout;

    @Override
    public String call() throws Exception {
        if (port < WhoIsConstants.MINIMUM_VALID_PORT || port > WhoIsConstants.MAXIMUM_VALID_PORT) {
            throw new IllegalArgumentException("port must be within the range [%s, %s]".formatted(WhoIsConstants.MINIMUM_VALID_PORT, WhoIsConstants.MAXIMUM_VALID_PORT));
        }
        if (timeout < WhoIsConstants.MINIMUM_REQUEST_TIMEOUT) {
            throw new IllegalArgumentException("timeout must be greater than %s seconds".formatted(WhoIsConstants.MINIMUM_REQUEST_TIMEOUT));
        }
        if (!WhoIsUtility.isRegistryValid(registry)) {
            throw new IllegalArgumentException("registry was either incorrectly formatted or not recognized");
        }
        Optional<String> registry;
        if (!this.registry.isBlank()) {
            registry = Optional.of(this.registry);
        } else if (isAddress) {
            registry = findAuthoritativeRegistry(target, "referrer:");
        } else {
            Optional<String> topLevelDomain = WhoIsUtility.extractTopLevelDomain(target);
            if (topLevelDomain.isEmpty()) {
                throw new IllegalArgumentException("top level domain could not be extracted from the target domain");
            }
            registry = findAuthoritativeRegistry(topLevelDomain.get(), "whois:");
        }
        if (registry.isEmpty()) {
            throw new IllegalArgumentException("registry could not be found for the target domain or address");
        }
        try (Socket socket = new Socket(registry.get(), port)) {
            OutputStream output = socket.getOutputStream();
            output.write("%s%s".formatted(target, System.lineSeparator()).getBytes());
            output.flush();
            try (BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                StringBuilder builder = new StringBuilder();
                String line;
                while ((line = input.readLine()) != null) {
                    builder.append(line);
                    builder.append(System.lineSeparator());
                }
                return builder.toString();
            }
        }
    }

    private static Optional<String> findAuthoritativeRegistry(String query, String field) throws IOException {
        String registry = null;
        try (Socket socket = new Socket(WhoIsConstants.REGISTRY_SERVER_ADDRESS, WhoIsConstants.REGISTRY_SERVER_PORT)) {
            OutputStream output = socket.getOutputStream();
            output.write("%s%s".formatted(query, System.lineSeparator()).getBytes());
            output.flush();
            try (BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                String line;
                while ((line = input.readLine()) != null) {
                    if (line.toLowerCase().startsWith(field)) {
                        registry = line.split(":")[1].trim();
                        break;
                    }
                }
            }
        }
        if (registry == null) {
            return Optional.empty();
        }
        return Optional.of(registry);
    }

}