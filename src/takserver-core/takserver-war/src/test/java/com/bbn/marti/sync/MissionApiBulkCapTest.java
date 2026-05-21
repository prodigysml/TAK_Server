package com.bbn.marti.sync;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.bbn.marti.sync.api.MissionApi;

/**
 * Boundary tests for the mission-keyword / content / log-entry caps. These
 * endpoints loop over caller-supplied lists with per-element DB writes,
 * cache invalidations, and mission-change broadcasts. Without caps, holders
 * of MISSION_WRITE (an operator-tier permission) can amplify a single PUT
 * into thousands of downstream operations (CWE-400, CWE-770).
 */
public class MissionApiBulkCapTest {

	@Test
	public void listSizeBoundary() {
		assertFalse(MissionApi.shouldRejectListSize(0, 256));
		assertFalse(MissionApi.shouldRejectListSize(256, 256));
		assertTrue(MissionApi.shouldRejectListSize(257, 256));
		assertTrue(MissionApi.shouldRejectListSize(1_000_000, 256));
	}

	@Test
	public void keywordsCapIsReasonable() {
		assertTrue(MissionApi.MAX_MISSION_KEYWORDS >= 16);
		assertTrue(MissionApi.MAX_MISSION_KEYWORDS <= 10_000);
	}

	@Test
	public void contentHashCapIsReasonable() {
		assertTrue(MissionApi.MAX_MISSION_CONTENT_HASHES >= 64);
		assertTrue(MissionApi.MAX_MISSION_CONTENT_HASHES <= 100_000);
	}

	@Test
	public void contentUidCapIsReasonable() {
		assertTrue(MissionApi.MAX_MISSION_CONTENT_UIDS >= 64);
		assertTrue(MissionApi.MAX_MISSION_CONTENT_UIDS <= 100_000);
	}

	@Test
	public void contentPathCapIsReasonable() {
		assertTrue(MissionApi.MAX_MISSION_CONTENT_PATHS >= 64);
		assertTrue(MissionApi.MAX_MISSION_CONTENT_PATHS <= 100_000);
	}

	@Test
	public void logEntryMissionNamesCapIsReasonable() {
		assertTrue(MissionApi.MAX_LOG_ENTRY_MISSION_NAMES >= 4);
		assertTrue(MissionApi.MAX_LOG_ENTRY_MISSION_NAMES <= 1024);
	}
}
