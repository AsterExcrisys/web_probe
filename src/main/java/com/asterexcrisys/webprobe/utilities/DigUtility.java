package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.DigConstants;
import com.asterexcrisys.webprobe.constants.GlobalConstants;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class DigUtility {

    public static Optional<Resolver[]> parseResolvers(String resolvers, int port) throws IOException {
        if (resolvers == null || resolvers.isBlank()) {
            return Optional.of(new Resolver[] {new SimpleResolver(DigConstants.DEFAULT_RESOLVER)});
        }
        List<Resolver> results = new ArrayList<>();
        for (String resolver : resolvers.split("@")) {
            if (!InetAddress.getByName(resolver).isReachable(GlobalConstants.DEFAULT_TIMEOUT)) {
                return Optional.empty();
            }
            Resolver result = new SimpleResolver(resolver);
            result.setPort(port);
            results.add(result);
        }
        return Optional.of(results.toArray(Resolver[]::new));
    }

}