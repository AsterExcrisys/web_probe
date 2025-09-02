package com.asterexcrisys.webprobe.constants;

public final class NMapConstants {

    public static final String VERSION = "1.0.0";
    public static final String DESCRIPTION = "Scans an host or a network to discover information about its ports or hosts.";
    public static final int SNAP_LENGTH = 65536;
    public static final int HANDLE_TIMEOUT = 10;
    public static final int LISTENER_TIMEOUT = 1000;
    public static final int LOOP_COUNT = 1;
    public static final byte[] DUMMY_PAYLOAD = new byte[] {80, 76, 65, 67, 69, 72, 79, 76, 68, 69, 82};
    public static final int NULL_PORT_NUMBER = -1;
    public static final int MINIMUM_PORT_NUMBER = 0;
    public static final int MAXIMUM_PORT_NUMBER = 100;
    public static final String ARP_FILTER = "arp and arp[6:2] = 2 and src host %s and ether dst %s and dst host %s";
    public static final String ICMP_FILTER = "icmp and icmp[0] = 0 and ether src %s and src host %s and ether dst %s and dst host %s";
    public static final String TCP_FILTER = "tcp and tcp[13] & 0x02 != 0 and ether src %s and src host %s and src port %s and ether dst %s and dst host %s and dst port %s";

}