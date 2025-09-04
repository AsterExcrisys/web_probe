package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.DirBusterConstants;
import com.asterexcrisys.webprobe.types.HttpMethod;
import com.asterexcrisys.webprobe.types.HttpStatus;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public final class DirBusterUtility {

    public static Optional<String> parseUrl(String url) throws IOException, InterruptedException {
        if (GlobalUtility.isUrlValid(url)) {
            return Optional.of(url.endsWith("/") ? url:url.concat("/"));
        } else {
            return Optional.empty();
        }
    }

    public static Optional<List<String>> parseContents(String contents) {
        if (contents == null || contents.isBlank()) {
            return Optional.empty();
        }
        List<String> results = new ArrayList<>();
        for (String content : contents.split("@")) {
            if (content == null || content.isBlank()) {
                continue;
            }
            results.add(content.trim());
        }
        if (results.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(results);
    }

    public static Optional<HttpMethod> parseMethod(String method) {
        if (method == null || method.isBlank()) {
            return Optional.empty();
        }
        if (!Pattern.matches(DirBusterConstants.METHOD_REGEX, method.toLowerCase())) {
            return Optional.empty();
        }
        return Optional.of(HttpMethod.valueOf(method.toUpperCase()));
    }

    public static boolean isStatusAllowed(HttpStatus status) {
        if (status == null) {
            return false;
        }
        return DirBusterConstants.ALLOWED_STATUSES.contains(status);
    }

}