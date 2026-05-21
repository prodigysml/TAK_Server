package com.bbn.marti.video;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Bounds the per-request video-collection cap used by
 * VideoManagerService.getVideoCollections. /Marti/api/video/** is accessible
 * to any authenticated caller per security-context.xml, and each connection
 * triggers XML inflation + nested filter loops -- an unbounded set is a
 * DoS amplifier (CWE-400, CWE-770).
 */
public class VideoManagerServiceCollectionCapTest {

	@Test
	public void zeroIsAccepted() {
		assertFalse(VideoManagerService.shouldTruncateConnectionSet(0, 1000));
	}

	@Test
	public void atCapAccepted() {
		assertFalse(VideoManagerService.shouldTruncateConnectionSet(1000, 1000));
	}

	@Test
	public void oneOverTruncated() {
		assertTrue(VideoManagerService.shouldTruncateConnectionSet(1001, 1000));
	}

	@Test
	public void floodTruncated() {
		assertTrue(VideoManagerService.shouldTruncateConnectionSet(1_000_000, 1000));
	}

	@Test
	public void defaultConnectionCapIsReasonable() {
		assertTrue(VideoManagerService.MAX_VIDEO_CONNECTIONS_PER_RESPONSE >= 100);
		assertTrue(VideoManagerService.MAX_VIDEO_CONNECTIONS_PER_RESPONSE <= 100_000);
	}

	@Test
	public void defaultFeedCapIsReasonable() {
		assertTrue(VideoManagerService.MAX_VIDEO_FEEDS_PER_CONNECTION >= 16);
		assertTrue(VideoManagerService.MAX_VIDEO_FEEDS_PER_CONNECTION <= 100_000);
	}
}
