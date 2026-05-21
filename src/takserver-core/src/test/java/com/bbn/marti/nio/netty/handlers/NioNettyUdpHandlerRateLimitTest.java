package com.bbn.marti.nio.netty.handlers;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the UDP flood mitigation helpers added to
 * NioNettyUdpHandler. These guard the per-packet size cap and the
 * per-source rate limiter that decide whether a datagram is parsed
 * (CWE-400). The Netty pipeline cannot be exercised in a plain unit
 * test, so the logic is tested via the package-private static helpers.
 */
public class NioNettyUdpHandlerRateLimitTest {

	@Before
	public void resetState() {
		NioNettyUdpHandler.resetRateState();
	}

	@Test
	public void zeroLengthPacketIsDropped() {
		assertTrue(NioNettyUdpHandler.shouldDropOversized(0, 1024));
	}

	@Test
	public void negativeLengthPacketIsDropped() {
		assertTrue(NioNettyUdpHandler.shouldDropOversized(-1, 1024));
	}

	@Test
	public void packetAtCapIsAccepted() {
		assertFalse(NioNettyUdpHandler.shouldDropOversized(1024, 1024));
	}

	@Test
	public void packetJustOverCapIsDropped() {
		assertTrue(NioNettyUdpHandler.shouldDropOversized(1025, 1024));
	}

	@Test
	public void packetWellWithinCapIsAccepted() {
		assertFalse(NioNettyUdpHandler.shouldDropOversized(100, 64 * 1024));
	}

	@Test
	public void nullSourceBypassesRateCheck() {
		// Defensive: if we can't determine the source, do not throttle.
		assertTrue(NioNettyUdpHandler.tryAcquireToken(null, 1_000L, 1, 1_000L));
		assertTrue(NioNettyUdpHandler.tryAcquireToken(null, 1_001L, 1, 1_000L));
	}

	@Test
	public void firstPacketAlwaysAdmitted() throws UnknownHostException {
		InetAddress src = InetAddress.getByName("10.0.0.1");
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 5_000L, 3, 1_000L));
	}

	@Test
	public void admitsUpToCapPerWindow() throws UnknownHostException {
		InetAddress src = InetAddress.getByName("10.0.0.2");
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 0L, 3, 1_000L));
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 0L, 3, 1_000L));
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 0L, 3, 1_000L));
		// 4th packet within same window must be rejected
		assertFalse(NioNettyUdpHandler.tryAcquireToken(src, 0L, 3, 1_000L));
	}

	@Test
	public void rollsWindowAfterIntervalElapses() throws UnknownHostException {
		InetAddress src = InetAddress.getByName("10.0.0.3");
		// burn cap
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 0L, 2, 1_000L));
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 0L, 2, 1_000L));
		assertFalse(NioNettyUdpHandler.tryAcquireToken(src, 0L, 2, 1_000L));
		// roll to next window
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 1_500L, 2, 1_000L));
		assertTrue(NioNettyUdpHandler.tryAcquireToken(src, 1_500L, 2, 1_000L));
		assertFalse(NioNettyUdpHandler.tryAcquireToken(src, 1_500L, 2, 1_000L));
	}

	@Test
	public void perSourceIsolation() throws UnknownHostException {
		InetAddress a = InetAddress.getByName("10.0.0.4");
		InetAddress b = InetAddress.getByName("10.0.0.5");
		// fully consume A's window
		assertTrue(NioNettyUdpHandler.tryAcquireToken(a, 100L, 1, 1_000L));
		assertFalse(NioNettyUdpHandler.tryAcquireToken(a, 100L, 1, 1_000L));
		// B is unaffected
		assertTrue(NioNettyUdpHandler.tryAcquireToken(b, 100L, 1, 1_000L));
	}
}
