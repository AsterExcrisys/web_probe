package com.asterexcrisys.webprobe.commands.nmap.subcommands;

import com.asterexcrisys.webprobe.constants.NMapConstants;
import com.asterexcrisys.webprobe.services.ArpPacketListener;
import com.asterexcrisys.webprobe.services.IcmpPacketListener;
import com.asterexcrisys.webprobe.services.ListenerTask;
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

@Command(name = "host", description = "Scans a network for reachable hosts.")
public class Host implements Callable<String> {

    @Parameters(index = "0", description = "The network to scan for reachable hosts.", arity = "1")
    private String network;

    @Override
    public String call() throws Exception {
        if (!NMapUtility.isLocalNetwork(network)) {
            throw new IllegalArgumentException("network is not local (cannot be directly accessed from one of this device's interfaces)");
        }
        Optional<List<String>> network = NMapUtility.parseNetworkHosts(this.network);
        if (network.isEmpty()) {
            throw new IllegalArgumentException("network was incorrectly formatted (make sure it follows the CIDR format)");
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
        InetAddress sourceIpAddress = NMapUtility.findIpAddress(networkInterface);
        MacAddress sourceMacAddress = NMapUtility.findMacAddress(networkInterface);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            while (!Thread.currentThread().isInterrupted() && !hosts.isEmpty()) {
                String host = hosts.poll();
                if (host == null) {
                    continue;
                }
                try {
                    InetAddress destinationIpAddress = InetAddress.getByName(host);
                    boolean isReachable = checkHostReachability(executor, networkInterface, sourceIpAddress, sourceMacAddress, destinationIpAddress);
                    scans.put(destinationIpAddress.toString(), isReachable);
                } catch (UnknownHostException exception) {
                    scans.put(host, false);
                }
            }
        }
    }

    private static boolean checkHostReachability(ExecutorService executor, PcapNetworkInterface networkInterface, InetAddress sourceIpAddress, MacAddress sourceMacAddress, InetAddress destinationIpAddress) throws NotOpenException, PcapNativeException, InterruptedException {
        if (destinationIpAddress.equals(sourceIpAddress)) {
            return true;
        }
        Optional<MacAddress> destinationMacAddress = resolveHostMacAddress(executor, networkInterface, sourceIpAddress, sourceMacAddress, destinationIpAddress);
        if (destinationMacAddress.isEmpty()) {
            return false;
        }
        try (
                PcapHandle sendHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT);
                PcapHandle receiveHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT)
        ) {
            receiveHandle.setFilter("icmp and icmp[0] = 0 and src host %s and ether src %s and dst host %s and ether dst %s".formatted(
                    Pcaps.toBpfString(destinationIpAddress),
                    Pcaps.toBpfString(destinationMacAddress.get()),
                    Pcaps.toBpfString(sourceIpAddress),
                    Pcaps.toBpfString(sourceMacAddress)
            ), BpfProgram.BpfCompileMode.OPTIMIZE);
            Future<Boolean> future = executor.submit(new ListenerTask<>(receiveHandle, new IcmpPacketListener(receiveHandle)));
            sendHandle.sendPacket(NMapUtility.buildIcmpPacket(
                    sourceIpAddress,
                    sourceMacAddress,
                    destinationIpAddress,
                    destinationMacAddress.get()
            ));
            try {
                return future.get(NMapConstants.LISTENER_TIMEOUT, TimeUnit.MILLISECONDS);
            } catch (ExecutionException | TimeoutException ignored) {
                receiveHandle.breakLoop();
                future.cancel(true);
                return false;
            }
        }
    }

    private static Optional<MacAddress> resolveHostMacAddress(ExecutorService executor, PcapNetworkInterface networkInterface, InetAddress sourceIpAddress, MacAddress sourceMacAddress, InetAddress destinationIpAddress) throws PcapNativeException, NotOpenException, InterruptedException {
        if (destinationIpAddress.equals(sourceIpAddress)) {
            return Optional.of(sourceMacAddress);
        }
        try (
                PcapHandle sendHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT);
                PcapHandle receiveHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT)
        ) {
            receiveHandle.setFilter("arp and arp[6:2] = 2 and src host %s and dst host %s and ether dst %s".formatted(
                    Pcaps.toBpfString(destinationIpAddress),
                    Pcaps.toBpfString(sourceIpAddress),
                    Pcaps.toBpfString(sourceMacAddress)
            ), BpfProgram.BpfCompileMode.OPTIMIZE);
            Future<Optional<MacAddress>> future = executor.submit(new ListenerTask<>(receiveHandle, new ArpPacketListener(receiveHandle)));
            sendHandle.sendPacket(NMapUtility.buildArpPacket(
                    sourceIpAddress,
                    sourceMacAddress,
                    destinationIpAddress
            ));
            try {
                return future.get(NMapConstants.LISTENER_TIMEOUT, TimeUnit.MILLISECONDS);
            } catch (ExecutionException | TimeoutException ignored) {
                receiveHandle.breakLoop();
                future.cancel(true);
                return Optional.empty();
            }
        }
    }

}