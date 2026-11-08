package com.bbn.marti.nio.protocol.connections;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import tak.server.cot.CotEventContainer;
import tak.server.cot.CotParser;

/**
 * An end tag that arrives before any start tag used to make add() throw from
 * substring(-1, n) and leave the stray data in the connection buffer, so the
 * next valid message on the same connection was spliced onto the junk and lost.
 */
public class StreamingCotProtocolFramingTest {

	private static final String EVENT =
			"<event version=\"2.0\" uid=\"u1\" type=\"a-f-G\" how=\"m-g\" time=\"2024-01-01T00:00:00Z\""
			+ " start=\"2024-01-01T00:00:00Z\" stale=\"2024-01-01T00:10:00Z\">"
			+ "<point lat=\"0\" lon=\"0\" hae=\"0\" ce=\"0\" le=\"0\"/><detail/></event>";

	@Test
	public void strayEndTagBeforeStartIsDroppedNotThrown() {
		StringBuffer buf = new StringBuffer();
		CotParser parser = new CotParser(false);

		List<CotEventContainer> first = StreamingCotProtocol.add(buf, "junk</event>", parser, null);
		assertEquals(0, first.size());
		assertEquals("", buf.toString());

		List<CotEventContainer> second = StreamingCotProtocol.add(buf, EVENT, parser, null);
		assertEquals(1, second.size());
		assertEquals("u1", second.get(0).getUid());
	}

	@Test
	public void strayEndTagFollowedByEventInSameChunk() {
		StringBuffer buf = new StringBuffer();
		List<CotEventContainer> out = StreamingCotProtocol.add(buf, "x</event>" + EVENT, new CotParser(false), null);
		assertEquals(1, out.size());
		assertEquals("u1", out.get(0).getUid());
	}
}
