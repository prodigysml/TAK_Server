package com.bbn.marti.nio.netty.handlers;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.base.Strings;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.util.CharsetUtil;

import org.apache.log4j.Logger;
import org.dom4j.Document;

import com.bbn.cot.CotParserCreator;
import com.bbn.marti.config.Input;
import com.bbn.marti.groups.GroupFederationUtil;
import com.bbn.marti.groups.MessagingUtilImpl;
import com.bbn.marti.nio.channel.ChannelHandler;
import com.bbn.marti.nio.channel.connections.UdpDataChannelHandler;
import com.bbn.marti.nio.channel.connections.UdpServerChannelHandler;
import com.bbn.marti.nio.listener.ProtocolListener;
import com.bbn.marti.nio.protocol.Protocol;
import com.bbn.marti.nio.protocol.base.AbstractBroadcastingProtocol;
import com.bbn.marti.nio.protocol.connections.SingleCotProtocol;
import com.bbn.marti.nio.protocol.connections.SingleProtobufOrCotProtocol;
import com.bbn.marti.remote.InputMetric;
import com.bbn.marti.remote.groups.ConnectionInfo;
import com.bbn.marti.remote.groups.GroupManager;
import com.bbn.marti.service.DistributedSubscriptionManager;
import com.bbn.marti.service.SubmissionService;
import com.bbn.marti.service.TransportCotEvent;
import com.bbn.marti.util.MessageConversionUtil;
import com.bbn.marti.util.MessagingDependencyInjectionProxy;
import com.bbn.marti.util.concurrent.future.AsyncFuture;

import tak.server.cot.CotEventContainer;
import tak.server.cot.CotParser;
import tak.server.federation.DistributedFederationManager;
import tak.server.qos.MessageDeliveryStrategy;

public class NioNettyUdpHandler extends MessageToMessageDecoder<DatagramPacket> {
	private final static Logger log = Logger.getLogger(NioNettyUdpHandler.class);

	// UDP inputs are reachable by unauthenticated remote senders; cap the
	// per-packet parse work to bound CPU spent on malicious or malformed
	// datagrams. The CoT XML envelope is typically under a few hundred
	// bytes; protobuf CoT is similar. Anything beyond this is rejected
	// without invoking the XML / protobuf parser. Overridable via system
	// property for operators with unusual deployments.
	static final int MAX_UDP_PACKET_BYTES = readIntProp(
			"tak.udp.maxPacketBytes", 64 * 1024);

	// Per-source-IP packets-per-window rate cap. Drops excess packets
	// before parsing; bucket is reset every window. Defaults are sized
	// for typical TAK client transmit rate (a few PLI / chat per second).
	static final int RATE_PACKETS_PER_WINDOW = readIntProp(
			"tak.udp.ratePackets", 500);
	static final long RATE_WINDOW_MILLIS = readLongProp(
			"tak.udp.rateWindowMillis", 1_000L);

	// Bound the per-source map so a flood from many spoofed source IPs
	// cannot itself exhaust memory. FIFO eviction when full.
	static final int RATE_MAP_MAX_ENTRIES = readIntProp(
			"tak.udp.rateMapMaxEntries", 4096);

	private static int readIntProp(String key, int dflt) {
		try { return Integer.parseInt(System.getProperty(key, Integer.toString(dflt))); }
		catch (Exception e) { return dflt; }
	}

	private static long readLongProp(String key, long dflt) {
		try { return Long.parseLong(System.getProperty(key, Long.toString(dflt))); }
		catch (Exception e) { return dflt; }
	}

	private static final Map<InetAddress, RateBucket> RATE_BUCKETS =
			java.util.Collections.synchronizedMap(new LinkedHashMap<InetAddress, RateBucket>(
					16, 0.75f, false) {
		private static final long serialVersionUID = 1L;
		@Override
		protected boolean removeEldestEntry(Map.Entry<InetAddress, RateBucket> eldest) {
			return size() > RATE_MAP_MAX_ENTRIES;
		}
	});

	private static final class RateBucket {
		final AtomicLong windowStartMillis = new AtomicLong();
		final AtomicLong count = new AtomicLong();
	}

	/**
	 * @return true if a datagram of {@code len} bytes should be dropped before
	 *         parsing because it exceeds the configured maximum.
	 */
	static boolean shouldDropOversized(int len, int max) {
		return len <= 0 || len > max;
	}

	/**
	 * Per-source token bucket. Returns true if a packet from {@code src} should
	 * be admitted, false if the rate cap has been reached for the current
	 * window. Visible for testing.
	 */
	static boolean tryAcquireToken(InetAddress src, long nowMillis,
			int packetsPerWindow, long windowMillis) {
		if (src == null) return true; // do not throttle when source is unknown
		RateBucket bucket = RATE_BUCKETS.computeIfAbsent(src, k -> new RateBucket());
		long start = bucket.windowStartMillis.get();
		if (nowMillis - start >= windowMillis) {
			// roll window. setting windowStartMillis after counting avoids a
			// race where a concurrent caller sees a fresh window but the
			// counter hasn't been reset yet.
			bucket.windowStartMillis.set(nowMillis);
			bucket.count.set(1L);
			return true;
		}
		long c = bucket.count.incrementAndGet();
		return c <= packetsPerWindow;
	}

	// Visible for testing
	static void resetRateState() {
		RATE_BUCKETS.clear();
	}

	protected MessagingUtilImpl messagingUtil;
	protected Protocol<CotEventContainer> protocol;
	protected volatile CotParser parser;
	protected Input input;
	protected ConcurrentLinkedQueue<ProtocolListener<CotEventContainer>> protocolListeners;
	protected AtomicBoolean protoSupported = new AtomicBoolean(false);
	
	public NioNettyUdpHandler(Input input) {
		this.input = input;
		this.parser = CotParserCreator.newInstance();
		
		TransportCotEvent transport = TransportCotEvent.findByID(input.getProtocol());
		if (transport == TransportCotEvent.COTPROTOMUDP)
			this.protoSupported.set(true);
	}
	
	@Override
	protected void decode(ChannelHandlerContext ctx, DatagramPacket packet, List<Object> out) throws Exception {
		try {
			InetSocketAddress sender = packet.sender();

			// SECURITY: bound per-packet parse work and per-source send rate
			// before invoking the XML / protobuf parser. UDP inputs cannot
			// authenticate the sender, so an external attacker can otherwise
			// force unbounded CPU spend by flooding crafted datagrams (CWE-400).
			int len = packet.content().readableBytes();
			if (shouldDropOversized(len, MAX_UDP_PACKET_BYTES)) {
				if (log.isDebugEnabled()) {
					log.debug("dropping oversized UDP datagram from " + sender
							+ ": " + len + " bytes (cap=" + MAX_UDP_PACKET_BYTES + ")");
				}
				return;
			}
			InetAddress src = sender != null ? sender.getAddress() : null;
			if (!tryAcquireToken(src, System.currentTimeMillis(),
					RATE_PACKETS_PER_WINDOW, RATE_WINDOW_MILLIS)) {
				if (log.isDebugEnabled()) {
					log.debug("rate-dropping UDP datagram from " + src
							+ "; cap=" + RATE_PACKETS_PER_WINDOW
							+ " packets per " + RATE_WINDOW_MILLIS + "ms");
				}
				return;
			}

			ConnectionInfo connectionInfo = new ConnectionInfo();
          
            connectionInfo.setConnectionId(MessageConversionUtil.getConnectionId(input));
            connectionInfo.setAddress(sender.getAddress().toString());
            connectionInfo.setTls(false);

            UdpDataChannelHandler handler = (UdpDataChannelHandler) new UdpDataChannelHandler()
                    .withAddress(sender)
                    .withLocalPort(input.getPort())
                    .withConnectionInfo(connectionInfo);

            handler.withInput(input);
            
            InputMetric inputMetric = SubmissionService.getInstance().getInputMetric(input.getName());
            if (inputMetric != null) {
                inputMetric.getMessagesReceived().incrementAndGet();
            }
                        
            if (protoSupported.get()) {
            	CotEventContainer cot = SingleProtobufOrCotProtocol.byteBufToCot(packet.content().nioBuffer(), handler, parser);
            	if (cot != null)
            		 createAdaptedNettyProtocol(handler).getProtocolListeners().forEach(listener -> listener.onDataReceived(cot, handler, protocol));
            } else {
            	CotEventContainer cot = SingleCotProtocol.byteBufToCot(packet.content().nioBuffer(), handler, parser);
            	if (cot != null)
            		createAdaptedNettyProtocol(handler).getProtocolListeners().forEach(listener -> listener.onDataReceived(cot, handler, protocol));
            }
   		} catch (Exception e) {
			log.error("cot error",e);
		}
	}
	
	protected AbstractBroadcastingProtocol<CotEventContainer> createAdaptedNettyProtocol(ChannelHandler channelHandler) {
		AbstractBroadcastingProtocol<CotEventContainer> protocol = new AbstractBroadcastingProtocol<CotEventContainer>() {
			@Override
			public void negotiate() {}

			@Override
			public void onConnect(ChannelHandler handler) {}

			@Override
			public void onDataReceived(ByteBuffer buffer, ChannelHandler handler) {}

			@Override
			public AsyncFuture<Integer> write(CotEventContainer data, ChannelHandler handler) {
				return null;
			}

			@Override
			public void onInboundClose(ChannelHandler handler) {}

			@Override
			public void onOutboundClose(ChannelHandler handler) {}

		};
		
		if (input.isArchiveOnly()) {
			protocol.addProtocolListener(
					SubmissionService.InputListenerAuxillaryRouter.onArchiveOnlyDataReceivedCallback
							.newInstance(channelHandler, protocol));
		}

		if (!input.isArchive()) {
			protocol.addProtocolListener(SubmissionService.InputListenerAuxillaryRouter.onNoArchiveDataReceivedCallback
					.newInstance(channelHandler, protocol));
		}

		protocol.addProtocolListener(SubmissionService.getInstance().onDataReceivedCallback.newInstance(channelHandler, protocol));
		
		return protocol;
	}
}
