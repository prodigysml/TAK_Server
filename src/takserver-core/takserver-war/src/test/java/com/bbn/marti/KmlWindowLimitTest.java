package com.bbn.marti;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.sql.Timestamp;

import org.junit.Test;

/**
 * KML export/query window bounds shared by LatestKMLServlet (secago) and
 * MissionKMLServlet (start/end/interval), both capped by tak.kml.maxSecAgo.
 */
public class KmlWindowLimitTest {

	private static final int MAX = 30 * 24 * 3600;

	@Test
	public void defaultMaxIsThirtyDays() {
		assertEquals(MAX, LatestKMLServlet.DEFAULT_MAX_SEC_AGO);
		if (System.getProperty("tak.kml.maxSecAgo") == null) {
			assertEquals(MAX, LatestKMLServlet.maxSecAgo());
		}
	}

	@Test
	public void zeroSecAgoBecomesMax() {
		// 0 used to drop the time filter entirely in the DAO
		assertEquals(MAX, LatestKMLServlet.effectiveSecAgo(0, MAX));
	}

	@Test
	public void overMaxSecAgoIsClamped() {
		assertEquals(MAX, LatestKMLServlet.effectiveSecAgo(MAX + 1, MAX));
		assertEquals(MAX, LatestKMLServlet.effectiveSecAgo(Integer.MAX_VALUE, MAX));
	}

	@Test
	public void inRangeSecAgoUnchanged() {
		assertEquals(1, LatestKMLServlet.effectiveSecAgo(1, MAX));
		assertEquals(3600, LatestKMLServlet.effectiveSecAgo(3600, MAX));
		assertEquals(MAX, LatestKMLServlet.effectiveSecAgo(MAX, MAX));
	}

	@Test(expected = IllegalArgumentException.class)
	public void negativeSecAgoRejected() {
		LatestKMLServlet.effectiveSecAgo(-1, MAX);
	}

	@Test
	public void windowAtMaxAccepted() {
		Timestamp end = new Timestamp(1_700_000_000_000L);
		Timestamp start = new Timestamp(end.getTime() - MAX * 1000L);
		assertFalse(MissionKMLServlet.isWindowTooLong(start, end, MAX));
	}

	@Test
	public void windowOverMaxRejected() {
		Timestamp end = new Timestamp(1_700_000_000_000L);
		Timestamp start = new Timestamp(end.getTime() - MAX * 1000L - 1);
		assertTrue(MissionKMLServlet.isWindowTooLong(start, end, MAX));
	}

	@Test
	public void epochToNowRejected() {
		assertTrue(MissionKMLServlet.isWindowTooLong(new Timestamp(0), new Timestamp(System.currentTimeMillis()), MAX));
	}

	@Test
	public void openEndedOrReversedWindowNotFlagged() {
		Timestamp t = new Timestamp(1_700_000_000_000L);
		assertFalse(MissionKMLServlet.isWindowTooLong(null, t, MAX));
		assertFalse(MissionKMLServlet.isWindowTooLong(t, null, MAX));
		assertFalse(MissionKMLServlet.isWindowTooLong(t, new Timestamp(0), MAX));
	}
}
