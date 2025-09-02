package com.asterexcrisys.webprobe.services;

import org.pcap4j.core.PacketListener;

public interface ResultListener<T> extends PacketListener {

    T result();

}