package com.asterexcrisys.webprobe.constants;

import java.util.Map;

public final class RootConstants {

    public static final String VERSION = "1.0.0";
    public static final String DESCRIPTION = "Groups together all major web-related commands, such as CURL or WHOIS.";
    public static final Map<String, String> COMMANDS = Map.of(
            "CURL", "Makes a HTTP(S) request to the specified url.",
            "DIG", "Makes a DNS request to the specified name server (resolver).",
            "WHOIS", "Makes a WhoIs request to the specified domain or address.",
            "DIRBUSTER", "Scans a domain for common files and directories to find the ones that (might) exist.",
            "NMAP", "Scans a domain or an address for open, closed, and filtered ports."
    );

}