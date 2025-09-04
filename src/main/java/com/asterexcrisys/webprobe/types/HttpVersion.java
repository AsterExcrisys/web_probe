package com.asterexcrisys.webprobe.types;

import java.net.http.HttpClient.Version;

public enum HttpVersion {

    V1((short) 1, true, Version.HTTP_1_1),
    V2((short) 2, true, Version.HTTP_2),
    V3((short) 3, false, null);

    private final short number;
    private final boolean isSupported;
    private final Version version;

    HttpVersion(short number, boolean isSupported, Version version) {
        this.number = number;
        this.isSupported = isSupported;
        this.version = version;
    }

    public int number() {
        return number;
    }

    public boolean isSupported() {
        return isSupported;
    }

    public Version version() {
        return version;
    }

    public static HttpVersion versionOf(short version) {
        for (HttpVersion httpVersion : HttpVersion.values()) {
            if (httpVersion.number() == version && httpVersion.isSupported()) {
                return httpVersion;
            }
        }
        return null;
    }

}