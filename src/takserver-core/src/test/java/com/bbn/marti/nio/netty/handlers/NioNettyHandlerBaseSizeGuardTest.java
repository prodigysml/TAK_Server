package com.bbn.marti.nio.netty.handlers;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Verifies the inbound TCP/TLS size guard added to NioNettyHandlerBase.
 * Per-message size is the only bound between an oversized read and the
 * CoT / protobuf parser, so the helper must reject negative or
 * over-cap lengths and accept everything in between (CWE-770, CWE-400).
 */
public class NioNettyHandlerBaseSizeGuardTest {

	@Test
	public void zeroIsAccepted() {
		// Zero-length reads are unusual but harmless; reject only on negative
		// or oversized inputs so the parser handles the empty case.
		assertFalse(NioNettyHandlerBase.shouldDropOversizedTcp(0, 1024));
	}

	@Test
	public void negativeIsDropped() {
		assertTrue(NioNettyHandlerBase.shouldDropOversizedTcp(-1, 1024));
	}

	@Test
	public void atCapAccepted() {
		assertFalse(NioNettyHandlerBase.shouldDropOversizedTcp(1024, 1024));
	}

	@Test
	public void oneByteOverDropped() {
		assertTrue(NioNettyHandlerBase.shouldDropOversizedTcp(1025, 1024));
	}

	@Test
	public void normalMessageAccepted() {
		assertFalse(NioNettyHandlerBase.shouldDropOversizedTcp(2048, 8 * 1024 * 1024));
	}

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(NioNettyHandlerBase.MAX_TCP_MESSAGE_BYTES >= 65_536);
		assertTrue(NioNettyHandlerBase.MAX_TCP_MESSAGE_BYTES <= 64 * 1024 * 1024);
	}
}
