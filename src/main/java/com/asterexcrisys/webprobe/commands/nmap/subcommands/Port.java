package com.asterexcrisys.webprobe.commands.nmap.subcommands;

import com.asterexcrisys.webprobe.constants.GlobalConstants;
import com.asterexcrisys.webprobe.constants.NMapConstants;
import com.asterexcrisys.webprobe.services.ArpPacketListener;
import com.asterexcrisys.webprobe.services.ListenerTask;
import com.asterexcrisys.webprobe.services.TcpPacketListener;
import com.asterexcrisys.webprobe.types.PortState;
import com.asterexcrisys.webprobe.utilities.NMapUtility;
import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Command;
import java.net.InetAddress;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@Command(name = "port", description = "Scans an host for reachable ports (open, closed, or filtered).")
public class Port implements Callable<String> {

    @Parameters(index = "0", description = "The host to be scanned for reachable ports.", arity = "1")
    private String host;

    @Override
    public String call() throws Exception {
        if (!NMapUtility.isLocalHost(host)) {
            throw new IllegalArgumentException("host is not local (cannot be directly accessed from one of this device's interfaces)");
        }
        InetAddress destinationIpAddress = InetAddress.getByName(host);
        Optional<MacAddress> destinationMacAddress = resolveHostMacAddress(destinationIpAddress);
        if (destinationMacAddress.isEmpty()) {
            throw new IllegalArgumentException("host was either incorrectly formatted or not a valid address");
        }
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            AtomicInteger ports = new AtomicInteger(GlobalConstants.MINIMUM_VALID_PORT);
            ConcurrentMap<Integer, PortState> scans = new ConcurrentHashMap<>();
            CountDownLatch latch = new CountDownLatch(10);
            for (int i = 0; i < 10; i++) {
                executor.submit(() -> {
                    try {
                        checkPortsReachability(ports, scans, destinationMacAddress.get(), destinationIpAddress);
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
                builder.append("Host scan successfully completed:");
            } else {
                executor.shutdownNow();
                builder.append("Host scan forcefully interrupted:");
            }
            builder.append(System.lineSeparator());
            builder.append(System.lineSeparator());
            scans.forEach((key, value) -> {
                switch (value) {
                    case OPEN -> builder.append("Port %s is open".formatted(key));
                    case CLOSED -> builder.append("Port %s is closed".formatted(key));
                    case FILTERED -> builder.append("Port %s is filtered".formatted(key));
                }
                builder.append(System.lineSeparator());
            });
            return builder.toString();
        }
    }

    private static Optional<MacAddress> resolveHostMacAddress(InetAddress destinationIpAddress) throws PcapNativeException, NotOpenException, InterruptedException {
        PcapNetworkInterface networkInterface = NMapUtility.findNetworkInterface();
        MacAddress sourceMacAddress = NMapUtility.findMacAddress(networkInterface);
        InetAddress sourceIpAddress = NMapUtility.findIpAddress(networkInterface);
        if (destinationIpAddress.equals(sourceIpAddress)) {
            return Optional.of(sourceMacAddress);
        }
        try (
                ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
                PcapHandle sendHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT);
                PcapHandle receiveHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT)
        ) {
            receiveHandle.setFilter(NMapConstants.ARP_FILTER.formatted(
                    Pcaps.toBpfString(destinationIpAddress),
                    Pcaps.toBpfString(sourceMacAddress),
                    Pcaps.toBpfString(sourceIpAddress)
            ), BpfProgram.BpfCompileMode.OPTIMIZE);
            Future<Optional<MacAddress>> future = executor.submit(new ListenerTask<>(receiveHandle, new ArpPacketListener(receiveHandle)));
            sendHandle.sendPacket(NMapUtility.buildArpPacket(
                    sourceMacAddress,
                    sourceIpAddress,
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

    private static void checkPortsReachability(AtomicInteger ports, ConcurrentMap<Integer, PortState> scans, MacAddress destinationMacAddress, InetAddress destinationIpAddress) throws NotOpenException, PcapNativeException, InterruptedException {
        PcapNetworkInterface networkInterface = NMapUtility.findNetworkInterface();
        MacAddress sourceMacAddress = NMapUtility.findMacAddress(networkInterface);
        InetAddress sourceIpAddress = NMapUtility.findIpAddress(networkInterface);
        int sourcePort = NMapUtility.findAvailablePort();
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            while (!Thread.currentThread().isInterrupted() && ports.get() != GlobalConstants.NULL_INVALID_PORT) {
                int destinationPort = ports.getAndUpdate((value) -> {
                    if (value == GlobalConstants.NULL_INVALID_PORT) {
                        return value;
                    }
                    if (value + 1 > GlobalConstants.MAXIMUM_VALID_PORT) {
                        return GlobalConstants.NULL_INVALID_PORT;
                    }
                    return value + 1;
                });
                if (destinationPort == GlobalConstants.NULL_INVALID_PORT) {
                    break;
                }
                PortState state = checkPortReachability(executor, networkInterface, sourceMacAddress, sourceIpAddress, sourcePort, destinationMacAddress, destinationIpAddress, destinationPort);
                scans.put(destinationPort, state);
            }
        }
    }

    private static PortState checkPortReachability(ExecutorService executor, PcapNetworkInterface networkInterface, MacAddress sourceMacAddress, InetAddress sourceIpAddress, int sourcePort, MacAddress destinationMacAddress, InetAddress destinationIpAddress, int destinationPort) throws NotOpenException, PcapNativeException, InterruptedException {
        if (destinationIpAddress.equals(sourceIpAddress) && destinationPort == sourcePort) {
            return PortState.OPEN;
        }
        try (
                PcapHandle sendHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT);
                PcapHandle receiveHandle = networkInterface.openLive(NMapConstants.SNAP_LENGTH, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, NMapConstants.HANDLE_TIMEOUT)
        ) {
            receiveHandle.setFilter(NMapConstants.TCP_FILTER.formatted(
                    Pcaps.toBpfString(destinationMacAddress),
                    Pcaps.toBpfString(destinationIpAddress),
                    destinationPort,
                    Pcaps.toBpfString(sourceMacAddress),
                    Pcaps.toBpfString(sourceIpAddress),
                    sourcePort
            ), BpfProgram.BpfCompileMode.OPTIMIZE);
            Future<PortState> future = executor.submit(new ListenerTask<>(receiveHandle, new TcpPacketListener(receiveHandle)));
            sendHandle.sendPacket(NMapUtility.buildTcpPacket(
                    sourceMacAddress,
                    sourceIpAddress,
                    sourcePort,
                    destinationMacAddress,
                    destinationIpAddress,
                    destinationPort
            ));
            try {
                return future.get(NMapConstants.LISTENER_TIMEOUT, TimeUnit.MILLISECONDS);
            } catch (ExecutionException | TimeoutException ignored) {
                receiveHandle.breakLoop();
                future.cancel(true);
                return PortState.FILTERED;
            }
        }
    }

}