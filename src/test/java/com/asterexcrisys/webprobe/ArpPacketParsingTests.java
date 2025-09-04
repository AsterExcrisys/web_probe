package com.asterexcrisys.webprobe;

import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.util.MacAddress;
import java.net.InetAddress;
import java.util.Optional;

public class ArpPacketParsingTests {

    private static PcapNetworkInterface networkInterface;

    @BeforeAll
    public static void initialize() throws Exception {
        networkInterface = NMapUtility.findNetworkInterface();
    }

    @Test
    public void tryParseValidArpPacket() {
        Assertions.assertDoesNotThrow(() -> Assertions.assertNotEquals(Optional.empty(), NMapUtility.parseArpPacket(NMapUtility.buildArpPacket(
                NMapUtility.findMacAddress(networkInterface),
                NMapUtility.findIpAddress(networkInterface),
                InetAddress.getByName("192.168.0.1")
        ))));
    }

    @Test
    public void tryParseInvalidIcmpPacket() {
        Assertions.assertDoesNotThrow(() -> {
            MacAddress sourceMacAddress = NMapUtility.findMacAddress(networkInterface);
            InetAddress sourceIpAddress = NMapUtility.findIpAddress(networkInterface);
            MacAddress destinationMacAddress = MacAddress.getByName("FF:FF:FF:FF:FF:FF");
            InetAddress destinationIpAddress = InetAddress.getByName("192.168.0.1");
            Optional<ArpPacket> packet = NMapUtility.parseArpPacket(NMapUtility.buildIcmpPacket(
                    sourceMacAddress,
                    sourceIpAddress,
                    destinationMacAddress,
                    destinationIpAddress
            ));
            Assertions.assertNotEquals(Optional.empty(), packet);
            Assertions.assertNotEquals(sourceMacAddress, packet.get().getHeader().getSrcHardwareAddr());
            Assertions.assertNotEquals(sourceIpAddress, packet.get().getHeader().getSrcProtocolAddr());
            Assertions.assertNotEquals(destinationMacAddress, packet.get().getHeader().getDstHardwareAddr());
            Assertions.assertNotEquals(destinationIpAddress, packet.get().getHeader().getDstProtocolAddr());
        });
    }

    @Test
    public void tryParseInvalidTcpPacket() {
        Assertions.assertDoesNotThrow(() -> {
            MacAddress sourceMacAddress = NMapUtility.findMacAddress(networkInterface);
            InetAddress sourceIpAddress = NMapUtility.findIpAddress(networkInterface);
            MacAddress destinationMacAddress = MacAddress.getByName("FF:FF:FF:FF:FF:FF");
            InetAddress destinationIpAddress = InetAddress.getByName("192.168.0.1");
            Optional<ArpPacket> packet = NMapUtility.parseArpPacket(NMapUtility.buildTcpPacket(
                    sourceMacAddress,
                    sourceIpAddress,
                    10000,
                    destinationMacAddress,
                    destinationIpAddress,
                    100
            ));
            Assertions.assertNotEquals(Optional.empty(), packet);
            Assertions.assertNotEquals(sourceMacAddress, packet.get().getHeader().getSrcHardwareAddr());
            Assertions.assertNotEquals(sourceIpAddress, packet.get().getHeader().getSrcProtocolAddr());
            Assertions.assertNotEquals(destinationMacAddress, packet.get().getHeader().getDstHardwareAddr());
            Assertions.assertNotEquals(destinationIpAddress, packet.get().getHeader().getDstProtocolAddr());
        });
    }

    @Test
    public void tryParseInvalidUnknownPacket() {
        Assertions.assertDoesNotThrow(() -> Assertions.assertEquals(Optional.empty(), NMapUtility.parseArpPacket(
                new UnknownPacket.Builder().rawData(new byte[0]).build()
        )));
    }

}