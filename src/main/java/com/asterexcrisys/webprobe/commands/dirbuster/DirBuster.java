package com.asterexcrisys.webprobe.commands.dirbuster;

import com.asterexcrisys.webprobe.constants.DirBusterConstants;
import com.asterexcrisys.webprobe.constants.GlobalConstants;
import com.asterexcrisys.webprobe.types.HttpMethod;
import com.asterexcrisys.webprobe.types.HttpStatus;
import com.asterexcrisys.webprobe.types.HttpVersion;
import com.asterexcrisys.webprobe.types.ScanResult;
import com.asterexcrisys.webprobe.utilities.DirBusterUtility;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Command;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;

@Command(name = "dirbuster", mixinStandardHelpOptions = true, version = DirBusterConstants.VERSION, description = DirBusterConstants.DESCRIPTION)
public class DirBuster implements Callable<String> {

    @Parameters(index = "0", description = "The url to be scanned for files and directories that (might) exist.", arity = "1")
    private String url;

    @Parameters(index = "1", description = "The contents to be scanned against the url.", arity = "1")
    private String contents;

    @Option(names = {"-m", "--method"}, description = "The method to use for the requests (optional).", defaultValue = "get")
    private String method;

    @Option(names = {"-t", "--timeout"}, description = "The timeout for the requests in milliseconds (optional).", defaultValue = "5000")
    private long timeout;

    @Option(names = {"-v", "--version"}, description = "The version of the HTTP(S) protocol to use (optional).", defaultValue = "2")
    private short version;

    @Override
    public String call() throws Exception {
        Optional<String> url = DirBusterUtility.parseUrl(this.url);
        if (url.isEmpty()) {
            throw new IllegalArgumentException("url was either incorrectly formatted or not recognized");
        }
        Optional<List<String>> contents = DirBusterUtility.parseContents(this.contents);
        if (contents.isEmpty()) {
            throw new IllegalArgumentException("contents were either incorrectly formatted or not recognized");
        }
        Optional<HttpMethod> method = DirBusterUtility.parseMethod(this.method);
        if (method.isEmpty()) {
            throw new IllegalArgumentException("method specified is not recognized or supported");
        }
        if (timeout < GlobalConstants.MINIMUM_REQUEST_TIMEOUT) {
            throw new IllegalArgumentException("timeout must be greater than %s seconds".formatted(GlobalConstants.MINIMUM_REQUEST_TIMEOUT));
        }
        HttpVersion version = HttpVersion.versionOf(this.version);
        if (version == null) {
            throw new IllegalArgumentException("version specified is not supported");
        }
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            BlockingQueue<String> paths = new LinkedBlockingQueue<>(contents.get());
            ConcurrentMap<String, ScanResult> scans = new ConcurrentHashMap<>();
            CountDownLatch latch = new CountDownLatch(10);
            for (int i = 0; i < 10; i++) {
                executor.submit(() -> {
                    try {
                        checkPathsReachability(paths, scans, url.get(), version, method.get(), timeout);
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                    } catch (IOException ignored) {

                    } finally {
                        latch.countDown();
                    }
                });
            }
            StringBuilder builder = new StringBuilder();
            if (latch.await(10, TimeUnit.MINUTES)) {
                builder.append("Content scan successfully completed:");
            } else {
                executor.shutdownNow();
                builder.append("Content scan forcefully interrupted:");
            }
            builder.append(System.lineSeparator());
            builder.append(System.lineSeparator());
            scans.forEach((key, value) -> {
                if (value.isFound()) {
                    builder.append("Path %s does exist: (%s, %s, %s (%s))".formatted(
                            key,
                            value.version(),
                            value.method(),
                            value.status().code(),
                            value.status()
                    ));
                } else {
                    builder.append("Path %s does not exist: (%s, %s, %s (%s))".formatted(
                            key,
                            value.version(),
                            value.method(),
                            value.status().code(),
                            value.status()
                    ));
                }
                builder.append(System.lineSeparator());
            });
            return builder.toString();
        }
    }

    private static void checkPathsReachability(BlockingQueue<String> paths, ConcurrentMap<String, ScanResult> scans, String url, HttpVersion version, HttpMethod method, long timeout) throws IOException, InterruptedException {
        while (!Thread.currentThread().isInterrupted() && !paths.isEmpty()) {
            String path = paths.poll();
            if (path == null) {
                continue;
            }
            path = url.concat(path);
            ScanResult result = checkPathReachability(path, version, method, timeout);
            scans.put(path, result);
        }
    }

    private static ScanResult checkPathReachability(String url, HttpVersion version, HttpMethod method, long timeout) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .method(method.name(), HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofMillis(timeout))
                    .version(version.version())
                    .build();
            HttpResponse<String> response = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );
            HttpStatus status = HttpStatus.codeOf(response.statusCode());
            return ScanResult.of(
                    version,
                    method,
                    status,
                    DirBusterConstants.ALLOWED_STATUSES.contains(status)
            );
        }
    }

}