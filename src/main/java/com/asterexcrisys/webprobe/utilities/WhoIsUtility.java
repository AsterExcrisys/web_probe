package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.WhoIsConstants;
import com.asterexcrisys.webprobe.types.HttpMethod;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

public final class WhoIsUtility {

    public static Optional<String> extractTopLevelDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return Optional.empty();
        }
        int index = domain.lastIndexOf('.');
        if (index == -1) {
            return Optional.of(domain);
        }
        return Optional.of(domain.substring(index + 1));
    }

    public static boolean isRegistryValid(String registry) throws IOException {
        if (registry == null || registry.isBlank()) {
            return true;
        }
        return InetAddress.getByName(registry).isReachable(WhoIsConstants.DEFAULT_TIMEOUT);
    }

    public static Optional<String> parseRegistry(String registry, boolean isAddress) throws IOException, InterruptedException {
        if (registry == null || registry.isBlank()) {
            return Optional.of(isAddress? WhoIsConstants.DEFAULT_ADDRESS_REGISTRY:WhoIsConstants.DEFAULT_DOMAIN_REGISTRY);
        }
        if (!isUrlValid(registry)) {
            return Optional.empty();
        }
        return Optional.of(registry);
    }

    private static boolean isUrlValid(String target) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(target))
                    .method(HttpMethod.HEAD.name(), HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(WhoIsConstants.DEFAULT_TIMEOUT))
                    .build();
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();
            return (status >= 200 && status < 400);
        }
    }

}