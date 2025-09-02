package com.asterexcrisys.webprobe.services;

import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;
import java.util.Objects;
import java.util.Optional;

public class ArpPacketListener implements ResultListener<Optional<MacAddress>> {

    private final PcapHandle handle;
    private MacAddress result;

    public ArpPacketListener(PcapHandle handle) {
        this.handle = Objects.requireNonNull(handle);
        result = null;
    }

    @Override
    public Optional<MacAddress> result() {
        if (result == null) {
            return Optional.empty();
        }
        return Optional.of(result);
    }

    @Override
    public void gotPacket(Packet packet) {
        Optional<ArpPacket> arpPacket = NMapUtility.parseArpPacket(packet);
        if (arpPacket.isEmpty() || !arpPacket.get().getHeader().getOperation().equals(ArpOperation.REPLY)) {
            return;
        }
        result = arpPacket.get().getHeader().getSrcHardwareAddr();
        try {
            handle.breakLoop();
        } catch (NotOpenException ignored) {

        }
    }

}