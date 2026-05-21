package com.bbn.marti.nio.netty.handlers;

import java.net.InetSocketAddress;

import com.bbn.marti.config.Input;
import com.bbn.marti.nio.channel.base.AbstractBroadcastingChannelHandler;

import io.netty.channel.ChannelHandlerContext;

public class NioNettyTcpServerHandler extends NioNettyStcpServerHandler {

	// SECURITY: cap concurrent inbound TCP connections so a connection flood
	// cannot exhaust the JVM via repeated codec/handler initialization
	// (CWE-400). Cap is intentionally generous; legitimate TAK clients
	// rarely exceed a few tens of thousands of concurrent sessions per node.
	private static final int MAX_ACTIVE_TCP_CONNECTIONS = Integer.parseInt(
		System.getProperty("tak.tcp.maxActiveConnections", "50000"));
	private static final java.util.concurrent.atomic.AtomicInteger ACTIVE_TCP_CONNECTIONS =
		new java.util.concurrent.atomic.AtomicInteger(0);

	public NioNettyTcpServerHandler(Input input) {
		super(input);
	}

	@Override
	public void channelActive(ChannelHandlerContext ctx) {
		if (ACTIVE_TCP_CONNECTIONS.get() >= MAX_ACTIVE_TCP_CONNECTIONS) {
			ctx.close();
			return;
		}
		ACTIVE_TCP_CONNECTIONS.incrementAndGet();
		ctx.channel().closeFuture().addListener(f -> ACTIVE_TCP_CONNECTIONS.decrementAndGet());
		remoteSocketAddress = (InetSocketAddress) ctx.channel().remoteAddress();
		localSocketAddress = (InetSocketAddress) ctx.channel().localAddress();
		nettyContext = ctx;
		createConnectionInfo();
		createAdaptedNettyProtocol();
		createAdaptedNettyHandler(connectionInfo);
		((AbstractBroadcastingChannelHandler) channelHandler).withHandlerType("NettyTCP");
		buildCallbacks();
		createAuthenticationCodecs();
		setReader();
		setWriter();
		setNegotiator();
	}
	
	
	@Override
	protected void setWriter() {
		writer = (data) -> {};
	}
	
	@Override
	protected void setNegotiator() {
		negotiator = () -> {};
	}
}
