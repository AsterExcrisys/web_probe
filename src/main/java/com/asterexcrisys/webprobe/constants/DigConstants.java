package com.asterexcrisys.webprobe.constants;

import java.util.Map;

public final class DigConstants {

    public static final String VERSION = "1.0.0";
    public static final String DESCRIPTION = "Makes a DNS request to the specified name server (resolver).";
    public static final Map<String, String> SUBCOMMANDS = Map.of(
            "DOMAIN", "Makes a DNS lookup request to the specified name server (resolver).",
            "ADDRESS", "Makes a DNS reverse-lookup request to the specified name server (resolver)."
    );
    public static final int MINIMUM_VALID_PORT = 1;
    public static final int MAXIMUM_VALID_PORT = 65535;
    public static final String DEFAULT_RESOLVER = "127.0.0.1";
    public static final int DEFAULT_TIMEOUT = 5000;

}