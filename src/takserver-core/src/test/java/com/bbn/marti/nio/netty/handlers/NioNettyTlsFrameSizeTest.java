package com.bbn.marti.nio.netty.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.nio.channel.ChannelHandler;

/**
 * The streaming protobuf parser on 8089 reads a varint frame length and then
 * buffers partial frames in "leftovers" until that many bytes arrive. The
 * per-read cap in NioNettyHandlerBase does not bound the declared frame
 * length, so a peer could declare ~2 GiB and stream data into the heap.
 * The declared length must be rejected (and the connection closed) when it
 * exceeds MAX_TCP_MESSAGE_BYTES.
 */
public class NioNettyTlsFrameSizeTest {

	private NioNettyTlsServerHandler handler;
	private ChannelHandler channel;

	@Before
	public void setUp() {
		// The real constructor pulls in CoreConfig/Ignite (TransportCotEvent ->
		// Resources), so allocate the handler without running it: a Mockito
		// spy-style instance that calls the real parser methods. The parser
		// state fields start at their zero values, as after construction.
		handler = mock(NioNettyTlsServerHandler.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
		channel = mock(ChannelHandler.class);
		handler.channelHandler = channel;
	}

	private static byte[] header(int size) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(0xbf);
		int v = size;
		while ((v & ~0x7F) != 0) {
			out.write((v & 0x7F) | 0x80);
			v >>>= 7;
		}
		out.write(v);
		return out.toByteArray();
	}

	private static byte[] concat(byte[] a, int extra) {
		byte[] r = new byte[a.length + extra];
		System.arraycopy(a, 0, r, 0, a.length);
		return r;
	}

	private ByteBuffer leftovers() throws Exception {
		Field f = NioNettyTlsServerHandler.class.getDeclaredField("leftovers");
		f.setAccessible(true);
		return (ByteBuffer) f.get(handler);
	}

	@Test
	public void oversizedDeclaredFrameClosesWithoutBuffering() throws Exception {
		int declared = NioNettyHandlerBase.MAX_TCP_MESSAGE_BYTES + 1;
		handler.convertAndSubmitProtoBufBytesAsCot(concat(header(declared), 4096));
		handler.convertAndSubmitProtoBufBytesAsCot(new byte[4096]);

		verify(channel, atLeastOnce()).forceClose();
		assertNull(leftovers());
	}

	@Test
	public void hugeDeclaredFrameClosesWithoutBuffering() throws Exception {
		handler.convertAndSubmitProtoBufBytesAsCot(concat(header(Integer.MAX_VALUE), 4096));

		verify(channel, atLeastOnce()).forceClose();
		assertNull(leftovers());
	}

	@Test
	public void partialFrameWithinCapIsBuffered() throws Exception {
		handler.convertAndSubmitProtoBufBytesAsCot(concat(header(100), 50));

		verify(channel, never()).forceClose();
		assertNotNull(leftovers());
		assertEquals(50, leftovers().remaining());
	}
}
