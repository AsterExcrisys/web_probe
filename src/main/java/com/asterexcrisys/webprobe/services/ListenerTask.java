package com.asterexcrisys.webprobe.services;

import com.asterexcrisys.webprobe.constants.NMapConstants;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import java.util.Objects;
import java.util.concurrent.Callable;

public class ListenerTask<T> implements Callable<T> {

    private final PcapHandle handle;
    private final ResultListener<T> listener;

    public ListenerTask(PcapHandle handle, ResultListener<T> listener) {
        this.handle = Objects.requireNonNull(handle);
        this.listener = Objects.requireNonNull(listener);
    }

    @Override
    public T call() throws NotOpenException, PcapNativeException {
        try {
            handle.loop(NMapConstants.LOOP_COUNT, listener);
        } catch (InterruptedException ignored) {
            handle.breakLoop();
            Thread.currentThread().interrupt();
        }
        return listener.result();
    }

}