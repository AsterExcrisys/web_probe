package com.asterexcrisys.webprobe.utilities;

import com.asterexcrisys.webprobe.constants.NMapConstants;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressString;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.*;

public class NMapUtility {

    public static boolean isLocalNetwork(String networkAddress) throws PcapNativeException {
        if (networkAddress == null || networkAddress.isBlank()) {
            return false;
        }
        PcapNetworkInterface networkInterface = findNetworkInterface();
        IPAddress localAddress = new IPAddressString(findIpAddress(networkInterface).getHostAddress()).getAddress(IPVersion.IPV4);
        IPAddress localNetworkMask = new IPAddressString(findNetworkMask(networkInterface).getHostAddress()).getAddress(IPVersion.IPV4);
        if (localAddress == null || localNetworkMask == null) {
            return false;
        }
        IPAddress localNetwork = localAddress.mask(localNetworkMask).toPrefixBlock(
                localNetworkMask.getBlockMaskPrefixLength(true)
        );
        IPAddress givenNetwork = new IPAddressString(networkAddress).getAddress(IPVersion.IPV4);
        if (localNetwork == null || givenNetwork == null) {
            return false;
        }
        if (!givenNetwork.isPrefixed()) {
            return localNetwork.equals(givenNetwork.mask(localNetworkMask).toPrefixBlock());
        } else {
            return localNetwork.equals(givenNetwork.toPrefixBlock());
        }
    }

    public static boolean isLocalHost(String hostAddress) throws PcapNativeException {
        if (hostAddress == null || hostAddress.isBlank()) {
            return false;
        }
        PcapNetworkInterface networkInterface = findNetworkInterface();
        IPAddress localAddress = new IPAddressString(findIpAddress(networkInterface).getHostAddress()).getAddress(IPVersion.IPV4);
        IPAddress localNetworkMask = new IPAddressString(findNetworkMask(networkInterface).getHostAddress()).getAddress(IPVersion.IPV4);
        if (localAddress == null || localNetworkMask == null) {
            return false;
        }
        IPAddress localNetwork = localAddress.mask(localNetworkMask).toPrefixBlock(
                localNetworkMask.getBlockMaskPrefixLength(true)
        );
        IPAddress givenHost = new IPAddressString(hostAddress).getAddress(IPVersion.IPV4);
        if (localNetwork == null || givenHost == null) {
            return false;
        }
        return givenHost.isIPAddress() && localNetwork.contains(givenHost);
    }

    public static Optional<List<String>> parseNetworkHosts(String networkAddress) {
        if (networkAddress == null || networkAddress.isBlank()) {
            return Optional.empty();
        }
        IPAddress network = new IPAddressString(networkAddress).getAddress(IPVersion.IPV4);
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
                        && device.getAddresses().stream().anyMatch((address) -> address.getAddress() != null && address.getAddress() instanceof Inet4Address);
            } catch (Exception exception) {
                return false;
            }
        }).findFirst().orElseThrow(() -> new PcapNativeException("no network interface found on the device"));
    }

    // TODO: check if the network is in the same network as the host
    public static InetAddress findNetworkMask(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return networkInterface.getAddresses().stream().filter((address) -> {
            try {
                return address.getAddress() instanceof Inet4Address;
            } catch (Exception exception) {
                return false;
            }
        }).findFirst().orElseThrow(() -> new PcapNativeException("no network mask found on the network interface")).getNetmask();
    }

    public static InetAddress findIpAddress(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return networkInterface.getAddresses().stream().filter((address) -> {
            try {
                return address.getAddress() instanceof Inet4Address;
            } catch (Exception exception) {
                return false;
            }
        }).findFirst().orElseThrow(() -> new PcapNativeException("no ip address found on the network interface")).getAddress();
    }

    public static MacAddress findMacAddress(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().stream().filter((address) -> {
            try {
                return address instanceof MacAddress;
            } catch (Exception exception) {
                return false;
            }
        }).findFirst().orElseThrow(() -> new PcapNativeException("no mac address found on the network interface")).getAddress());
    }

    public static Packet buildArpPacket(InetAddress sourceIpAddress, MacAddress sourceMacAddress, InetAddress destinationIpAddress) {
        ArpPacket.Builder arpPacket = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
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
        IcmpV4EchoPacket.Builder icmpV4EchoPacket = new IcmpV4EchoPacket.Builder()
                .identifier((short) 1)
                .sequenceNumber((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(NMapConstants.DUMMY_PAYLOAD));
        IcmpV4CommonPacket.Builder icmpV4CommonPacket = new IcmpV4CommonPacket.Builder()
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(icmpV4EchoPacket)
                .correctChecksumAtBuild(true);
        IpV4Packet.Builder ipV4Packet = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 1)
                .ttl((byte) 64)
                .protocol(IpNumber.ICMPV4)
                .srcAddr((Inet4Address) sourceIpAddress)
                .dstAddr((Inet4Address) destinationIpAddress)
                .payloadBuilder(icmpV4CommonPacket)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);
        EthernetPacket.Builder ethernetPacket = new EthernetPacket.Builder()
                .type(EtherType.IPV4)
                .payloadBuilder(ipV4Packet)
                .paddingAtBuild(true)
                .srcAddr(sourceMacAddress)
                .dstAddr(destinationMacAddress);
        return ethernetPacket.build();
    }

    // TODO: implement the builder for the TCP SYN packet to be used for port scanning
    public static Packet buildTcpPacket() {
        return null;
    }

    public static Optional<ArpPacket> parseArpPacket(Packet packet) {
        if (packet == null) {
            return Optional.empty();
        }
        try {
            EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0, packet.length());
            Packet payload = ethernetPacket.getPayload();
            if (payload == null) {
                return Optional.empty();
            }
            return Optional.of(ArpPacket.newPacket(payload.getRawData(), 0, payload.length()));
        } catch (IllegalRawDataException exception) {
            return Optional.empty();
        }
    }

    // TODO: fix the issue with the IpV4Packet parsing of the TOS field
    public static Optional<IcmpV4CommonPacket> parseIcmpPacket(Packet packet) {
        if (packet == null) {
            return Optional.empty();
        }
        try {
            EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0, packet.length());
            Packet payload = ethernetPacket.getPayload();
            if (payload == null) {
                return Optional.empty();
            }
            /*IpV4Packet ipV4Packet = IpV4Packet.newPacket(payload.getRawData(), 0, payload.length());
            payload = ipV4Packet.getPayload();
            if (payload == null) {
                return Optional.empty();
            }*/
            return Optional.of(IcmpV4CommonPacket.newPacket(payload.getRawData(), 20, payload.length() - 20));
        } catch (IllegalRawDataException exception) {
            return Optional.empty();
        }
    }

    public static Optional<TcpPacket> parseTcpPacket(Packet packet) {
        return Optional.empty();
    }

}