package com.asterexcrisys.webprobe.commands.curl.subcommands;

import com.asterexcrisys.webprobe.constants.GlobalConstants;
import com.asterexcrisys.webprobe.types.HttpMethod;
import com.asterexcrisys.webprobe.types.HttpVersion;
import com.asterexcrisys.webprobe.utilities.CUrlUtility;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Command;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Callable;

@Command(name = "options", description = "Makes a HTTP(S) OPTIONS request to the specified URL.")
public class Options implements Callable<String> {

    @Parameters(index = "0", description = "The url where the request is to be forwarded.", arity = "1")
    private String url;

    @Option(names = {"-h", "--headers"}, description = "The headers to add onto the request (optional).", defaultValue = "")
    private String headers;

    @Option(names = {"-p", "--parameters"}, description = "The parameters to add onto the request (optional).", defaultValue = "")
    private String parameters;

    @Option(names = {"-t", "--timeout"}, description = "The timeout for the request in milliseconds (optional).", defaultValue = "5000")
    private long timeout;

    @Option(names = {"-v", "--version"}, description = "The version of the HTTP(S) protocol to use (optional).", defaultValue = "2")
    private short version;

    @Override
    public String call() throws Exception {
        Optional<String[]> headers = CUrlUtility.parseHeaders(this.headers);
        if (headers.isEmpty()) {
            throw new IllegalArgumentException("headers are incorrectly formatted");
        }
        if (timeout < GlobalConstants.MINIMUM_REQUEST_TIMEOUT) {
            throw new IllegalArgumentException("timeout must be greater than %s seconds".formatted(GlobalConstants.MINIMUM_REQUEST_TIMEOUT));
        }
        HttpVersion version = HttpVersion.versionOf(this.version);
        if (version == null) {
            throw new IllegalArgumentException("version specified is not supported");
        }
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .headers(headers.get())
                    .uri(URI.create("%s?%s".formatted(url, parameters)))
                    .method(HttpMethod.OPTIONS.name(), HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofMillis(timeout))
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