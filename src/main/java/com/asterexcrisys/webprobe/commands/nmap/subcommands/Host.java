package com.asterexcrisys.webprobe.commands.nmap.subcommands;

import com.asterexcrisys.webprobe.constants.NMapConstants;
import com.asterexcrisys.webprobe.services.ArpPacketListener;
import com.asterexcrisys.webprobe.services.IcmpPacketListener;
import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Command;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

@Command(name = "host", description = "Scans a network for reachable hosts.")
public class Host implements Callable<String> {

    @Parameters(index = "0", description = "The network to scan for reachable hosts.", arity = "1")
    private String network;

    @Override
    public String call() throws Exception {
        Optional<List<String>> network = NMapUtility.parseNetworkHosts(this.network);
        if (network.isEmpty()) {
            throw new IllegalArgumentException("network was incorrectly formatted");
        }
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            BlockingQueue<String> hosts = new LinkedBlockingQueue<>(network.get());
            ConcurrentMap<String, Boolean> scans = new ConcurrentHashMap<>();
            CountDownLatch latch = new CountDownLatch(10);
            for (int i = 0; i < 10; i++) {
                executor.submit(() -> {
                    try {
                        checkHostsReachability(hosts, scans);
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                    } catch (NotOpenException | PcapNativeException ignored) {

                    } finally {
                        latch.countDown();
                    }
                });
            }
            StringBuilder builder = new StringBuilder();
            if (latch.await(10, TimeUnit.MINUTES)) {
                builder.append("Network scan successfully completed:");
            } else {
                executor.shutdownNow();
                builder.append("Network scan forcefully interrupted:");
            }
            builder.append(System.lineSeparator());
            builder.append(System.lineSeparator());
            scans.forEach((key, value) -> {
                if (value) {
                    builder.append("%s is up".formatted(key));
                } else {
                    builder.append("%s is down or non-existent".formatted(key));
                }
                builder.append(System.lineSeparator());
            });
            return builder.toString();
        }
    }

    private static void checkHostsReachability(BlockingQueue<String> hosts, ConcurrentMap<String, Boolean> scans) throws NotOpenException, PcapNativeException, InterruptedException {
        PcapNetworkInterface networkInterface = NMapUtility.findNetworkInterface();
        while (!Thread.currentThread().isInterrupted() && !hosts.isEmpty()) {
            String host = hosts.poll();
            if (host == null) {
                break;
            }
            try {
                InetAddress address = InetAddress.getByName(host);
                boolean isReachable = checkHostReachability(networkInterface, address);
                scans.put(address.toString(), isReachable);
            } catch (UnknownHostException exception) {
                scans.put(host, false);
            }
        }
    }

    private static boolean checkHostReachability(PcapNetworkInterface networkInterface, InetAddress destinationIpAddress) throws NotOpenException, PcapNativeException, InterruptedException {
        Optional<MacAddress> destinationMacAddress = resolveHostMacAddress(networkInterface, destinationIpAddress);
        if (destinationMacAddress.isEmpty()) {
            return false;
        }
        try (PcapHandle handle = networkInterface.openLive(NMapConstants.DEFAULT_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.MINIMUM_REQUEST_TIMEOUT)) {
            handle.setFilter("icmp and src host %s".formatted(Pcaps.toBpfString(destinationIpAddress)), BpfProgram.BpfCompileMode.OPTIMIZE);
            handle.sendPacket(NMapUtility.buildIcmpPacket(
                    networkInterface.getAddresses().getFirst().getAddress(),
                    MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress()),
                    destinationIpAddress,
                    destinationMacAddress.get()
            ));
            AtomicBoolean isReachable = new AtomicBoolean(false);
            handle.loop(1, new IcmpPacketListener(isReachable));
            return isReachable.get();
        }
    }

    private static Optional<MacAddress> resolveHostMacAddress(PcapNetworkInterface networkInterface, InetAddress destinationIpAddress) throws PcapNativeException, NotOpenException, InterruptedException {
        try (PcapHandle handle = networkInterface.openLive(NMapConstants.DEFAULT_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.MINIMUM_REQUEST_TIMEOUT)) {
            handle.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE);
            handle.sendPacket(NMapUtility.buildArpPacket(
                    networkInterface.getAddresses().getFirst().getAddress(),
                    MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().getFirst().getAddress()),
                    destinationIpAddress
            ));
            ArpPacketListener listener = new ArpPacketListener(handle, destinationIpAddress);
            handle.loop(1, listener);
            return listener.result();
        }
    }

}