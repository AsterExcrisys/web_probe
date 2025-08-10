package com.asterexcrisys.webprobe.commands.whois.subcommands;

import com.asterexcrisys.webprobe.constants.WhoIsConstants;
import com.asterexcrisys.webprobe.types.HttpMethod;
import com.asterexcrisys.webprobe.types.HttpVersion;
import com.asterexcrisys.webprobe.utilities.WhoIsUtility;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Callable;

@Command(name = "secure", description = "Makes a secure WHOIS request (RDAP) for the specified domain or address.")
public class Secure implements Callable<String> {

    @Parameters(index = "0", description = "The domain name or address to use for the request.", arity = "1")
    private String target;

    @Option(names = {"-r", "--registry"}, description = "The registry to use for the request (optional).", defaultValue = "")
    private String registry;

    @Option(names = {"-a", "--address"}, description = "The flag to signal whether the target is a domain or an address (optional).", defaultValue = "false")
    private boolean isAddress;

    @Option(names = {"-t", "--timeout"}, description = "The timeout for the request in seconds (optional).", defaultValue = "5000")
    private long timeout;

    @Option(names = {"-v", "--version"}, description = "The version of the HTTP(S) protocol to use (optional).", defaultValue = "2")
    private short version;

    @Override
    public String call() throws Exception {
        if (timeout < WhoIsConstants.MINIMUM_REQUEST_TIMEOUT) {
            throw new IllegalArgumentException("timeout must be greater than %s seconds".formatted(WhoIsConstants.MINIMUM_REQUEST_TIMEOUT));
        }
        HttpVersion version = HttpVersion.versionOf(this.version);
        if (version == null) {
            throw new IllegalArgumentException("version specified is not supported");
        }
        Optional<String> registry = WhoIsUtility.parseRegistry(this.registry, isAddress);
        if (registry.isEmpty()) {
            throw new IllegalArgumentException("registry was either incorrectly formatted or not recognized");
        }
        Redirect policy = this.registry.isBlank()? Redirect.ALWAYS:Redirect.NEVER;
        try (HttpClient client = HttpClient.newBuilder().followRedirects(policy).build()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("%s/%s".formatted(registry.get(), target)))
                    .method(HttpMethod.GET.name(), HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(timeout))
                    .version(version.version())
                    .build();
            HttpResponse<String> response = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );
            return response.body();
        }
    }

}