package com.asterexcrisys.webprobe.constants;

import com.asterexcrisys.webprobe.types.HttpStatus;
import java.util.List;

public final class DirBusterConstants {

    public static final String VERSION = "1.0.0";
    public static final String DESCRIPTION = "Scans a domain for common files and directories to find the ones that (might) exist.";
    public static final String URL_REGEX = "^((http((s)?))://)((www\\.)?)[a-zA-Z0-9_.]{2,256}\\.[a-zA-Z0-9]{2,6}((/([a-zA-Z0-9/@_\\-+.*:~ ]*))?)$";
    public static final String METHOD_REGEX = "^(get|post|put|patch|delete|head|options|connect|trace)$";
    public static final List<HttpStatus> ALLOWED_STATUSES = List.of(
            HttpStatus.CONTINUE,
            HttpStatus.SWITCHING_PROTOCOLS,
            HttpStatus.OK,
            HttpStatus.CREATED,
            HttpStatus.ACCEPTED,
            HttpStatus.NO_CONTENT,
            HttpStatus.MOVED_PERMANENTLY,
            HttpStatus.FOUND,
            HttpStatus.TEMPORARY_REDIRECT,
            HttpStatus.PERMANENT_REDIRECT,
            HttpStatus.BAD_REQUEST,
            HttpStatus.UNAUTHORIZED,
            HttpStatus.FORBIDDEN,
            HttpStatus.METHOD_NOT_ALLOWED,
            HttpStatus.GONE
    );

}