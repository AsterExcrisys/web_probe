package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.GlobalConstants;
import com.asterexcrisys.webprobe.constants.WhoIsConstants;
import java.io.IOException;
import java.net.InetAddress;
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
        return InetAddress.getByName(registry).isReachable(GlobalConstants.DEFAULT_TIMEOUT);
    }

    public static Optional<String> parseRegistry(String registry, boolean isAddress) throws IOException, InterruptedException {
        if (registry == null || registry.isBlank()) {
            return Optional.of(isAddress? WhoIsConstants.DEFAULT_ADDRESS_REGISTRY:WhoIsConstants.DEFAULT_DOMAIN_REGISTRY);
        }
        if (!GlobalUtility.isUrlValid(registry)) {
            return Optional.empty();
        }
        return Optional.of(registry);
    }

}