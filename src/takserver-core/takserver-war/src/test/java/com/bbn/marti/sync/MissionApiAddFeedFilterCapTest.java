package com.bbn.marti.sync;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import com.bbn.marti.sync.api.MissionApi;

/**
 * Bounds the addFeed / addFeedByGuid filter-payload caps in MissionApi.
 * Both endpoints accept caller-supplied JSON (filterCotTypes) and a list of
 * polygon points; without bounds these become parsing/iteration DoS
 * primitives (CWE-400). Caller must have MISSION_WRITE on the target
 * mission, so this is an operator-tier surface.
 */
public class MissionApiAddFeedFilterCapTest {

	@Test
	public void nullsAreAccepted() {
		assertFalse(MissionApi.shouldRejectFeedFilterPayload(null, null, 64_000, 1024));
	}

	@Test
	public void emptyValuesAreAccepted() {
		assertFalse(MissionApi.shouldRejectFeedFilterPayload(
				"", Collections.emptyList(), 64_000, 1024));
	}

	@Test
	public void atSerializedCapAccepted() {
		String json = repeat('a', 64_000);
		assertFalse(MissionApi.shouldRejectFeedFilterPayload(json, null, 64_000, 1024));
	}

	@Test
	public void overSerializedCapRejected() {
		String json = repeat('a', 64_001);
		assertTrue(MissionApi.shouldRejectFeedFilterPayload(json, null, 64_000, 1024));
	}

	@Test
	public void atPolygonCapAccepted() {
		List<String> points = new ArrayList<>();
		for (int i = 0; i < 1024; i++) points.add("0,0");
		assertFalse(MissionApi.shouldRejectFeedFilterPayload(null, points, 64_000, 1024));
	}

	@Test
	public void overPolygonCapRejected() {
		List<String> points = new ArrayList<>();
		for (int i = 0; i < 1025; i++) points.add("0,0");
		assertTrue(MissionApi.shouldRejectFeedFilterPayload(null, points, 64_000, 1024));
	}

	@Test
	public void postParseCountCap() {
		assertFalse(MissionApi.shouldRejectFeedFilterCount(0, 256));
		assertFalse(MissionApi.shouldRejectFeedFilterCount(256, 256));
		assertTrue(MissionApi.shouldRejectFeedFilterCount(257, 256));
		assertTrue(MissionApi.shouldRejectFeedFilterCount(1_000_000, 256));
	}

	@Test
	public void defaultCapsAreReasonable() {
		assertTrue(MissionApi.MAX_FEED_FILTER_COT_TYPES_BYTES >= 1024);
		assertTrue(MissionApi.MAX_FEED_FILTER_COT_TYPES_BYTES <= 16 * 1024 * 1024);
		assertTrue(MissionApi.MAX_FEED_FILTER_COT_TYPES_COUNT >= 16);
		assertTrue(MissionApi.MAX_FEED_FILTER_COT_TYPES_COUNT <= 100_000);
		assertTrue(MissionApi.MAX_FEED_FILTER_POLYGON_POINTS >= 16);
		assertTrue(MissionApi.MAX_FEED_FILTER_POLYGON_POINTS <= 1_000_000);
	}

	private static String repeat(char c, int n) {
		StringBuilder sb = new StringBuilder(n);
		for (int i = 0; i < n; i++) sb.append(c);
		return sb.toString();
	}
}
