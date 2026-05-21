package com.bbn.marti;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Bounds the parameter-count check used by ResubscribeServlet.doPost. Each
 * request parameter opens a fresh JDBC connection in removeSubscription, so
 * an unbounded loop is a DoS primitive (CWE-400).
 */
public class ResubscribeServletParamCapTest {

	@Test
	public void zeroIsAccepted() {
		assertFalse(ResubscribeServlet.shouldRejectParamCount(0, 256));
	}

	@Test
	public void atCapAccepted() {
		assertFalse(ResubscribeServlet.shouldRejectParamCount(256, 256));
	}

	@Test
	public void oneOverRejected() {
		assertTrue(ResubscribeServlet.shouldRejectParamCount(257, 256));
	}

	@Test
	public void largeFloodRejected() {
		assertTrue(ResubscribeServlet.shouldRejectParamCount(100_000, 256));
	}

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(ResubscribeServlet.MAX_RESUBSCRIBE_PARAMS >= 16);
		assertTrue(ResubscribeServlet.MAX_RESUBSCRIBE_PARAMS <= 4096);
	}
}
