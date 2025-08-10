package com.asterexcrisys.webprobe.services;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;
import java.net.InetAddress;
import java.util.Objects;
import java.util.Optional;

public class ArpPacketListener implements PacketListener {

    private final PcapHandle handle;
    private final InetAddress address;
    private MacAddress result;

    public ArpPacketListener(PcapHandle handle, InetAddress address) {
        this.handle = Objects.requireNonNull(handle);
        this.address = Objects.requireNonNull(address);
    }

    public Optional<MacAddress> result() {
        if (result == null) {
            return Optional.empty();
        }
        return Optional.of(result);
    }

    @Override
    public void gotPacket(Packet packet) {
        if (!packet.contains(ArpPacket.class)) {
            return;
        }
        ArpPacket arpPacket = packet.get(ArpPacket.class);
        if (!arpPacket.getHeader().getOperation().equals(ArpOperation.REPLY) || !arpPacket.getHeader().getDstProtocolAddr().equals(address)) {
            return;
        }
        result = arpPacket.getHeader().getDstHardwareAddr();
        try {
            handle.breakLoop();
        } catch (NotOpenException ignored) {

        }
    }

}