package com.asterexcrisys.webprobe.services;

import com.asterexcrisys.webprobe.types.PortState;
import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import java.util.Objects;
import java.util.Optional;

public class TcpPacketListener implements ResultListener<PortState> {

    private final PcapHandle handle;
    private PortState result;

    public TcpPacketListener(PcapHandle handle) {
        this.handle = Objects.requireNonNull(handle);
        result = PortState.FILTERED;
    }

    @Override
    public PortState result() {
        return result;
    }

    @Override
    public void gotPacket(Packet packet) {
        Optional<TcpPacket> tcpPacket = NMapUtility.parseTcpPacket(packet);
        if (tcpPacket.isEmpty() || !tcpPacket.get().getHeader().getSyn()) {
            return;
        }
        if (tcpPacket.get().getHeader().getRst()) {
            result = PortState.CLOSED;
        } else {
            result = PortState.OPEN;
        }
        try {
            handle.breakLoop();
        } catch (NotOpenException ignored) {

        }
    }

}