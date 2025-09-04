package com.asterexcrisys.webprobe;

import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.junit.jupiter.api.BeforeAll;
import org.pcap4j.core.PcapNetworkInterface;

public class IcmpPacketParsingTests {

    private static PcapNetworkInterface networkInterface;

    @BeforeAll
    public static void initialize() throws Exception {
        networkInterface = NMapUtility.findNetworkInterface();
    }

}