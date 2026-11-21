package com.bbn.marti.remote.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ExpirationWindowTest {

	private static final long NOW = 1_800_000_000L;
	private static final long WINDOW = ExpirationWindow.DEFAULT_MAX_WINDOW_SECONDS;

	@Test
	public void clearingValuesAreAllowed() {
		assertTrue(ExpirationWindow.isAllowed(null, NOW, WINDOW));
		assertTrue(ExpirationWindow.isAllowed(0L, NOW, WINDOW));
		assertTrue(ExpirationWindow.isAllowed(-1L, NOW, WINDOW));
	}

	@Test
	public void insideWindowIsAllowed() {
		assertTrue(ExpirationWindow.isAllowed(NOW + 3600, NOW, WINDOW));
		assertTrue(ExpirationWindow.isAllowed(NOW + WINDOW, NOW, WINDOW));
		assertTrue(ExpirationWindow.isAllowed(NOW - WINDOW, NOW, WINDOW));
	}

	@Test
	public void outsideWindowIsRejected() {
		assertFalse(ExpirationWindow.isAllowed(NOW + WINDOW + 1, NOW, WINDOW));
		assertFalse(ExpirationWindow.isAllowed(NOW - WINDOW - 1, NOW, WINDOW));
		assertFalse(ExpirationWindow.isAllowed(Long.MAX_VALUE, NOW, WINDOW));
	}

	@Test
	public void currentTimeOverloadUsesTenYearDefault() {
		long now = System.currentTimeMillis() / 1000L;
		assertTrue(ExpirationWindow.isAllowed(now + 86_400L));
		assertFalse(ExpirationWindow.isAllowed(now + 11L * 365L * 24L * 3600L));
	}

	@Test
	public void toMillisConverts() {
		assertEquals(NOW * 1000L, ExpirationWindow.toMillis(NOW));
	}

	@Test(expected = IllegalArgumentException.class)
	public void toMillisRejectsOverflow() {
		ExpirationWindow.toMillis(Long.MAX_VALUE / 1000L + 1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void toMillisRejectsNegativeOverflow() {
		ExpirationWindow.toMillis(Long.MIN_VALUE / 1000L - 1);
	}
}
