package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.DirBusterConstants;
import com.asterexcrisys.webprobe.constants.GlobalConstants;
import com.asterexcrisys.webprobe.types.HttpMethod;
import com.asterexcrisys.webprobe.types.HttpStatus;
import com.asterexcrisys.webprobe.types.HttpVersion;
import org.pcap4j.core.PcapNativeException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.regex.Pattern;

public final class GlobalUtility {

    public static boolean isUrlValid(String url) throws IOException, InterruptedException {
        if (url == null || url.isBlank()) {
            return false;
        }
        if (!Pattern.matches(DirBusterConstants.URL_REGEX, url.toLowerCase())) {
            return false;
        }
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .method(HttpMethod.OPTIONS.name(), HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(GlobalConstants.MINIMUM_REQUEST_TIMEOUT))
                    .version(HttpVersion.V2.version())
                    .build();
            HttpResponse<String> response = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );
            return DirBusterConstants.ALLOWED_STATUSES.contains(HttpStatus.codeOf(response.statusCode()));
        }
    }

    public static String findDefaultGateway() throws PcapNativeException {
        return parseDefaultGateway().orElseThrow(() -> new PcapNativeException("no default gateway found on this device"));
    }

    private static Optional<String> parseDefaultGateway() {
        String operativeSystem = System.getProperty("os.name", null);
        if (operativeSystem == null) {
            return Optional.empty();
        }
        operativeSystem = operativeSystem.trim().toLowerCase();
        if (operativeSystem.contains("win")) {
            return parseDefaultGatewayOnWindows();
        } else if (operativeSystem.contains("nux") || operativeSystem.contains("nix")) {
            return parseDefaultGatewayOnLinux();
        } else if (operativeSystem.contains("mac")) {
            return parseDefaultGatewayOnMac();
        } else {
            return Optional.empty();
        }
    }

    private static Optional<String> parseDefaultGatewayOnWindows() {
        try {
            Process process = new ProcessBuilder("route", "print", "0.0.0.0").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (!line.startsWith("0.0.0.0")) {
                        continue;
                    }
                    String[] parts = line.split("\\s+");
                    if (parts.length > 2) {
                        return Optional.ofNullable(parts[2]);
                    }
                }
            }
            return Optional.empty();
        } catch (Exception exception) {
            return Optional.empty();
        }
    }

    private static Optional<String> parseDefaultGatewayOnLinux() {
        try {
            Process process = new ProcessBuilder("ip", "route", "show", "default").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (!line.startsWith("default")) {
                        continue;
                    }
                    String[] parts = line.split("\\s+");
                    for (int i = 0; i < parts.length; i++) {
                        if (parts[i].equals("via") && parts.length > i + 1) {
                            return Optional.ofNullable(parts[i + 1]);
                        }
                    }
                }
            }
            return Optional.empty();
        } catch (Exception exception) {
            return Optional.empty();
        }
    }

    private static Optional<String> parseDefaultGatewayOnMac() {
        try {
            Process process = new ProcessBuilder("route", "get", "default").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (!line.startsWith("gateway:")) {
                        continue;
                    }
                    String[] parts = line.split("\\s+");
                    if (parts.length > 1) {
                        return Optional.ofNullable(parts[1]);
                    }
                }
            }
            return Optional.empty();
        } catch (Exception exception) {
            return Optional.empty();
        }
    }

}