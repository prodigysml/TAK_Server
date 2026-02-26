package com.bbn.marti.nio.quic;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bbn.marti.config.Input;
import com.bbn.marti.nio.netty.initializers.NioNettyInitializer;
import com.bbn.marti.remote.config.CoreConfigFacade;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicConnectionEvent;
import io.netty.incubator.codec.quic.QuicServerCodecBuilder;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicStreamChannel;
import io.netty.incubator.codec.quic.QuicTokenHandler;

public class QuicStreamingServer {
	private static final Logger log = LoggerFactory.getLogger(QuicStreamingServer.class);
	private static final int HMAC_TOKEN_LENGTH = 32; // SHA-256 output
	private static final byte[] TOKEN_KEY;

	static {
		TOKEN_KEY = new byte[32];
		new SecureRandom().nextBytes(TOKEN_KEY);
	}

	private final Map<String, InetSocketAddress> clientAddressMap = new ConcurrentHashMap<>();
	private final Map<String, NioNettyQuicServerHandler> clientHandlerMap = new ConcurrentHashMap<>();

	private ScheduledFuture<?> timeoutSchedulerFuture;
	private final int highwaterMark;

	private Input input;
	private Channel channel;

	
	public QuicStreamingServer(Input input, int highMark) {
		this.input = input;
		this.highwaterMark = highMark;
	}


	public void start() {
		new Thread(() -> {
			try {
				QuicSslContext context = (QuicSslContext) NioNettyInitializer.Pipeline.initializer.quicServer(
						input, CoreConfigFacade.getInstance().getRemoteConfiguration().getSecurity().getTls()).getSslContext();
						
				NioEventLoopGroup group = new NioEventLoopGroup(1);
				ChannelHandler codec = new QuicServerCodecBuilder().sslContext(context)
		                .maxIdleTimeout(input.getQuicConnectionTimeoutSeconds(), TimeUnit.SECONDS)
						// Only allow at most x bytes of incoming stream data to be buffered for the whole connection 
						// (that is, data that is not yet read by the application) and will allow more data to be received
						// as the buffer is consumed by the application. 
		                .initialMaxData(highwaterMark)
		                // bytes of incoming stream data to be buffered for each locally-initiated bidirectional stream 
		                // (that is, data that is not yet read by the application) 
		                // and will allow more data to be received as the buffer is consumed by the application.
		                .initialMaxStreamDataBidirectionalLocal(highwaterMark)
		                .initialMaxStreamDataBidirectionalRemote(highwaterMark)
		                .initialMaxStreamsBidirectional(1)
		                .initialMaxStreamsUnidirectional(0)
		                .initialMaxStreamDataUnidirectional(0)
		                .tokenHandler(new QuicTokenHandler() {
							@Override
							public boolean writeToken(ByteBuf out, ByteBuf dcid, InetSocketAddress address) {
								try {
									byte[] addressBytes = address.getAddress().getAddress();
									Mac mac = Mac.getInstance("HmacSHA256");
									mac.init(new SecretKeySpec(TOKEN_KEY, "HmacSHA256"));
									mac.update(addressBytes);
									byte[] hmac = mac.doFinal();
									out.writeBytes(hmac);
									return true;
								} catch (Exception e) {
									log.error("Error writing QUIC retry token", e);
									return false;
								}
							}

							@Override
							public int validateToken(ByteBuf token, InetSocketAddress address) {
								if (token.readableBytes() != HMAC_TOKEN_LENGTH) {
									return -1;
								}
								try {
									byte[] tokenBytes = new byte[HMAC_TOKEN_LENGTH];
									token.readBytes(tokenBytes);
									byte[] addressBytes = address.getAddress().getAddress();
									Mac mac = Mac.getInstance("HmacSHA256");
									mac.init(new SecretKeySpec(TOKEN_KEY, "HmacSHA256"));
									mac.update(addressBytes);
									byte[] expected = mac.doFinal();
									if (Arrays.equals(tokenBytes, expected)) {
										return 0;
									}
									return -1;
								} catch (Exception e) {
									log.error("Error validating QUIC retry token", e);
									return -1;
								}
							}

							@Override
							public int maxTokenLength() {
								return HMAC_TOKEN_LENGTH;
							}
		                })
						.handler(new ChannelInboundHandlerAdapter() {
							@Override
							public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
								super.userEventTriggered(ctx, evt);
								// save the client address
								if (evt instanceof QuicConnectionEvent) {
									QuicConnectionEvent event = (QuicConnectionEvent) evt;
									clientAddressMap.put(ctx.channel().id().asLongText(), (InetSocketAddress) event.newAddress());
								}
							}

							@Override
							public void channelActive(ChannelHandlerContext ctx) {
								QuicChannel channel = (QuicChannel) ctx.channel();
								// Create streams etc.. (right now the client creates the takstream)
							}

							// use one channel to accept all connections
							@Override
							public boolean isSharable() {
								return true;
							}

							@Override
							public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
								super.channelUnregistered(ctx);
								// clear local data
								try {
									clientAddressMap.remove(ctx.channel().id().asLongText());
									clientHandlerMap.remove(ctx.channel().id().asLongText());
								} catch (Exception e) {
									log.error("Error clearing connection state", e);
								}
							}

							@Override
							public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
								super.exceptionCaught(ctx, cause);
								log.error("Quic Channel level exception:" + cause);
								ctx.close();
							}
						})
						.streamHandler(new ChannelInitializer<QuicStreamChannel>() {
							@Override
		                    protected void initChannel(QuicStreamChannel ch)  {
								NioNettyQuicServerHandler quicHandler = new NioNettyQuicServerHandler(input, clientAddressMap);
								
								clientHandlerMap.put(ch.parent().id().asLongText(), quicHandler);
								
		                        ch.pipeline()
		                        	.addLast(new ByteArrayDecoder())
		                        	.addLast(new ByteArrayEncoder())
		                        	.addLast(quicHandler);
		                    }
		                }).build();
				try {
					Bootstrap bs = new Bootstrap();
					channel = bs.group(group)
							.channel(NioDatagramChannel.class)
							.handler(codec)
							.bind(new InetSocketAddress(input.getPort())).sync().channel();
					
					channel.closeFuture().sync();
				} finally {
					group.shutdownGracefully();
				}
			}
			catch (Exception e) {
				log.error("quic server error ", e);
			}
		}).start();
	}
	
	public void stop() {
		log.info("Shutting down quic server " + input );
		
		try {
			channel.close();
		} catch (Exception e) {
			log.error("error shutting down quic server",e);
		}
		
		try {
			if (timeoutSchedulerFuture != null) {
				timeoutSchedulerFuture.cancel(true);
			}
		} catch (Exception e) {
			log.error("error shutting down quic server client timeout scheduler");
		}
	}

}
