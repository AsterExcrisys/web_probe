package com.asterexcrisys.webprobe.services;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

public class IcmpPacketListener implements PacketListener {

    private final AtomicBoolean isReachable;

    public IcmpPacketListener(AtomicBoolean isReachable) {
        this.isReachable = Objects.requireNonNull(isReachable);
    }

    @Override
    public void gotPacket(Packet packet) {
        if (!packet.contains(IcmpV4CommonPacket.class)) {
            return;
        }
        IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
        if (icmpPacket.getHeader().getType() == IcmpV4Type.ECHO_REPLY) {
            isReachable.set(true);
        } else if (icmpPacket.getHeader().getType() == IcmpV4Type.TIME_EXCEEDED) {
            isReachable.set(false);
        }
    }

}