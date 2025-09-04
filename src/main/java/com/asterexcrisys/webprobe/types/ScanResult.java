package com.asterexcrisys.webprobe.types;

public record ScanResult(HttpVersion version, HttpMethod method, HttpStatus status, boolean isFound) {

    public static ScanResult of(HttpVersion version, HttpMethod method, HttpStatus status, boolean isFound) {
        return new ScanResult(version, method, status, isFound);
    }

}