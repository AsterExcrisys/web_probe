package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.CUrlConstants;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class CUrlUtility {

    public static Optional<String[]> parseHeaders(String headers) {
        if (headers == null || headers.isBlank()) {
            return Optional.of(new String[] {"User-Agent", CUrlConstants.USER_AGENT});
        }
        List<String> results = new ArrayList<>();
        boolean hasUserAgent = false;
        for (String header : headers.split("&")) {
            String[] parts = header.split("=", 2);
            if (parts.length != 2) {
                return Optional.empty();
            }
            String key = parts[0].trim();
            String value = parts[1].trim();
            if (key.equalsIgnoreCase("User-Agent")) {
                hasUserAgent = true;
            }
            results.add(key);
            results.add(value);
        }
        if (!hasUserAgent) {
            results.add("User-Agent");
            results.add(CUrlConstants.USER_AGENT);
        }
        return Optional.of(results.toArray(String[]::new));
    }

}