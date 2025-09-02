package com.asterexcrisys.webprobe.services;

import com.asterexcrisys.webprobe.constants.NMapConstants;
import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import java.util.Objects;
import java.util.Optional;

public class IcmpPacketListener implements ResultListener<Boolean> {

    private final PcapHandle handle;
    private boolean result;

    public IcmpPacketListener(PcapHandle handle) {
        this.handle = Objects.requireNonNull(handle);
        result = false;
    }

    @Override
    public Boolean result() {
        return result;
    }

    @Override
    public void gotPacket(Packet packet) {
        Optional<IcmpV4EchoReplyPacket> icmpV4EchoReplyPacket = parseIcmpEchoReplyPacket(packet);
        if (icmpV4EchoReplyPacket.isEmpty()) {
            return;
        }
        Packet payload = icmpV4EchoReplyPacket.get().getPayload();
        if (payload == null || !validateIcmpEchoReplyPayload(payload.getRawData(), NMapConstants.DUMMY_PAYLOAD)) {
            return;
        }
        result = true;
        try {
            handle.breakLoop();
        } catch (NotOpenException ignored) {

        }
    }

    private Optional<IcmpV4EchoReplyPacket> parseIcmpEchoReplyPacket(Packet packet) {
        Optional<IcmpV4CommonPacket> icmpV4CommonPacket = NMapUtility.parseIcmpPacket(packet);
        if (icmpV4CommonPacket.isEmpty() || icmpV4CommonPacket.get().getHeader().getType() != IcmpV4Type.ECHO_REPLY) {
            return Optional.empty();
        }
        Packet payload = icmpV4CommonPacket.get().getPayload();
        if (payload == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(IcmpV4EchoReplyPacket.newPacket(payload.getRawData(), 0, payload.length()));
        } catch (IllegalRawDataException exception) {
            return Optional.empty();
        }
    }

    private boolean validateIcmpEchoReplyPayload(byte[] actualPayload, byte[] expectedPayload) {
        if (actualPayload == null || expectedPayload == null || actualPayload.length < expectedPayload.length) {
            return false;
        }
        for (int i = 0; i < expectedPayload.length; i++) {
            if (actualPayload[i] != expectedPayload[i]) {
                return false;
            }
        }
        return true;
    }

}