package com.bbn.marti.video;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * The create path must enforce the same connection/feed caps as the read path,
 * before any DB insert or XML marshalling happens.
 */
public class VideoManagerServiceCreateCapTest {

	private static VideoCollections collections(int connections, int feedsEach) {
		VideoCollections vc = new VideoCollections();
		for (int i = 0; i < connections; i++) {
			VideoConnection c = new VideoConnection();
			for (int j = 0; j < feedsEach; j++) {
				c.getFeeds().add(new FeedV2());
			}
			vc.getVideoConnections().add(c);
		}
		return vc;
	}

	private static void assertRejected(VideoCollections vc, int maxConnections, int maxFeeds) {
		try {
			VideoManagerService.validateCreateRequest(vc, maxConnections, maxFeeds);
			fail("expected IllegalArgumentException");
		} catch (IllegalArgumentException expected) {
			// mapped to 400 by CustomExceptionHandler
		}
	}

	@Test
	public void nullAndEmptyAccepted() {
		VideoManagerService.validateCreateRequest(null, 10, 10);
		VideoManagerService.validateCreateRequest(new VideoCollections(), 10, 10);
	}

	@Test
	public void atCapsAccepted() {
		VideoManagerService.validateCreateRequest(collections(10, 5), 10, 5);
	}

	@Test
	public void tooManyConnectionsRejected() {
		assertRejected(collections(11, 0), 10, 5);
	}

	@Test
	public void tooManyFeedsInOneConnectionRejected() {
		VideoCollections vc = collections(3, 1);
		VideoConnection big = new VideoConnection();
		for (int j = 0; j < 6; j++) {
			big.getFeeds().add(new FeedV2());
		}
		vc.getVideoConnections().add(big);
		assertRejected(vc, 10, 5);
	}

	@Test
	public void nullConnectionEntryTolerated() {
		VideoCollections vc = collections(1, 1);
		vc.getVideoConnections().add(null);
		VideoManagerService.validateCreateRequest(vc, 10, 5);
		assertEquals(2, vc.getVideoConnections().size());
	}

	@Test
	public void defaultCapsAreUsedByCreate() {
		assertTrue(VideoManagerService.MAX_VIDEO_CONNECTIONS_PER_RESPONSE > 0);
		assertRejected(collections(VideoManagerService.MAX_VIDEO_CONNECTIONS_PER_RESPONSE + 1, 0),
				VideoManagerService.MAX_VIDEO_CONNECTIONS_PER_RESPONSE,
				VideoManagerService.MAX_VIDEO_FEEDS_PER_CONNECTION);
	}
}
