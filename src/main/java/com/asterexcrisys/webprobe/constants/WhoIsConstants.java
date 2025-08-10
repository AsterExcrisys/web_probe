package com.asterexcrisys.webprobe.constants;

import java.util.Map;

public final class WhoIsConstants {

    public static final String VERSION = "1.0.0";
    public static final String DESCRIPTION = "Makes a WhoIs request for the specified domain or address.";
    public static final Map<String, String> SUBCOMMANDS = Map.of(
            "DEFAULT", "Makes a default WhoIs request (non-RDAP) for the specified domain or address.",
            "SECURE", "Makes a secure WhoIs request (RDAP) for the specified domain or address."
    );
    public static final String REGISTRY_SERVER_ADDRESS = "whois.iana.org";
    public static final int REGISTRY_SERVER_PORT = 43;
    public static final String DEFAULT_ADDRESS_REGISTRY = "https://rdap.org/ip";
    public static final String DEFAULT_DOMAIN_REGISTRY = "https://rdap.org/domain";
    public static final int MINIMUM_VALID_PORT = 1;
    public static final int MAXIMUM_VALID_PORT = 65535;
    public static final long MINIMUM_REQUEST_TIMEOUT = 1000;
    public static final int DEFAULT_TIMEOUT = 5000;

}