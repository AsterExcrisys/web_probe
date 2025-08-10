package com.asterexcrisys.webprobe.utilities;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.*;

public class NMapUtility {

    public static Optional<List<String>> parseNetworkHosts(String networkAddress) {
        if (networkAddress == null || networkAddress.isBlank()) {
            return Optional.empty();
        }
        IPAddress network = new IPAddressString(networkAddress).getAddress();
        if (network == null) {
            return Optional.empty();
        }
        Iterator<? extends IPAddress> iterator = network.withoutPrefixLength().iterator();
        List<String> hosts = new ArrayList<>();
        while(iterator.hasNext()) {
            hosts.add(iterator.next().toString());
        }
        if (hosts.size() <= 2) {
            return Optional.of(Collections.emptyList());
        }
        hosts.removeFirst();
        hosts.removeLast();
        return Optional.of(hosts);
    }

    public static PcapNetworkInterface findNetworkInterface() throws PcapNativeException {
        return Pcaps.findAllDevs().stream().filter((device) -> {
            try {
                return !device.getAddresses().isEmpty()
                        && device.getAddresses().stream().anyMatch((address) -> address.getAddress() != null
                        && address.getAddress() instanceof Inet4Address);
            } catch (Exception exception) {
                return false;
            }
        }).findFirst().orElseThrow(() -> new PcapNativeException("no network interface found on the device"));
    }

    public static Packet buildArpPacket(InetAddress sourceIpAddress, MacAddress sourceMacAddress, InetAddress destinationIpAddress) {
        ArpPacket.Builder arpPacket = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcProtocolAddr(sourceIpAddress)
                .srcHardwareAddr(sourceMacAddress)
                .dstProtocolAddr(destinationIpAddress)
                .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS);
        EthernetPacket.Builder ethernetPacket = new EthernetPacket.Builder()
                .type(EtherType.ARP)
                .payloadBuilder(arpPacket)
                .paddingAtBuild(true)
                .srcAddr(sourceMacAddress)
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS);
        return ethernetPacket.build();
    }

    public static Packet buildIcmpPacket(InetAddress sourceIpAddress, MacAddress sourceMacAddress, InetAddress destinationIpAddress, MacAddress destinationMacAddress) {
        IcmpV4EchoPacket.Builder echoPacket = new IcmpV4EchoPacket.Builder()
                .identifier((short) 1)
                .sequenceNumber((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(new byte[] {1, 2, 3, 4}));
        IcmpV4CommonPacket.Builder icmpPacket = new IcmpV4CommonPacket.Builder()
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoPacket)
                .correctChecksumAtBuild(true);
        IpV4Packet.Builder ipv4Packet = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 100)
                .ttl((byte) 64)
                .protocol(IpNumber.ICMPV4)
                .srcAddr((Inet4Address) sourceIpAddress)
                .dstAddr((Inet4Address) destinationIpAddress)
                .payloadBuilder(icmpPacket)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);
        EthernetPacket.Builder ethernetPacket = new EthernetPacket.Builder()
                .type(EtherType.IPV4)
                .payloadBuilder(ipv4Packet)
                .paddingAtBuild(true)
                .srcAddr(sourceMacAddress)
                .dstAddr(destinationMacAddress);
        return ethernetPacket.build();
    }

    public static Packet buildTcpSynPacket() {
        return null;
    }

}