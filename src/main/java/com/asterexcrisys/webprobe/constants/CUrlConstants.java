package com.asterexcrisys.webprobe.constants;

import java.util.Map;

public final class CUrlConstants {

    public static final String VERSION = "1.0.0";
    public static final String DESCRIPTION = "Makes a HTTP(S) request to the specified url.";
    public static final Map<String, String> SUBCOMMANDS = Map.of(
            "GET", "Makes a HTTP(S) GET request to the specified URL.",
            "POST", "Makes a HTTP(S) POST request to the specified URL.",
            "PUT", "Makes a HTTP(S) PUT request to the specified URL.",
            "PATCH", "Makes a HTTP(S) PATCH request to the specified URL.",
            "DELETE", "Makes a HTTP(S) DELETE request to the specified URL.",
            "HEAD", "Makes a HTTP(S) HEAD request to the specified URL.",
            "OPTIONS", "Makes a HTTP(S) OPTIONS request to the specified URL.",
            "TRACE", "Makes a HTTP(S) TRACE request to the specified URL."
    );
    public static final String USER_AGENT = "WebProbe/1.0.0";

}