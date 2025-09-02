package com.asterexcrisys.webprobe.services;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;
import java.util.Objects;

public class TcpPacketListener implements ResultListener<Boolean> {

    private final PcapHandle handle;
    private boolean result;

    public TcpPacketListener(PcapHandle handle) {
        this.handle = Objects.requireNonNull(handle);
        result = false;
    }

    @Override
    public Boolean result() {
        return result;
    }

    @Override
    public void gotPacket(Packet packet) {

    }

}