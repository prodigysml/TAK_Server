package com.bbn.marti.citrap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Bounds caller-controlled report-query inputs on /citrap and
 * /citrap/subscribe. maxReportCount feeds straight into the SQL LIMIT;
 * comma-separated keywords/type/callsign each expand into an OR predicate
 * per term (CWE-400, CWE-770).
 */
public class CITrapReportAPICapTest {

	@Test
	public void clampNull() {
		assertEquals("1000", CITrapReportAPI.clampMaxReportCount(null, 1000));
	}

	@Test
	public void clampEmpty() {
		assertEquals("1000", CITrapReportAPI.clampMaxReportCount("", 1000));
	}

	@Test
	public void clampUnderCap() {
		assertEquals("50", CITrapReportAPI.clampMaxReportCount("50", 1000));
	}

	@Test
	public void clampAtCap() {
		assertEquals("1000", CITrapReportAPI.clampMaxReportCount("1000", 1000));
	}

	@Test
	public void clampOverCap() {
		assertEquals("1000", CITrapReportAPI.clampMaxReportCount("1000000", 1000));
	}

	@Test
	public void clampNegativeToZero() {
		assertEquals("0", CITrapReportAPI.clampMaxReportCount("-5", 1000));
	}

	@Test
	public void clampGarbageToCap() {
		assertEquals("1000", CITrapReportAPI.clampMaxReportCount("not-a-number", 1000));
	}

	@Test
	public void filterTermsNullAccepted() {
		assertFalse(CITrapReportAPI.shouldRejectFilterTerms(null, 64));
	}

	@Test
	public void filterTermsEmptyAccepted() {
		assertFalse(CITrapReportAPI.shouldRejectFilterTerms("", 64));
	}

	@Test
	public void filterTermsAtCapAccepted() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 64; i++) {
			if (i > 0) sb.append(',');
			sb.append('a');
		}
		assertFalse(CITrapReportAPI.shouldRejectFilterTerms(sb.toString(), 64));
	}

	@Test
	public void filterTermsOverCapRejected() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 65; i++) {
			if (i > 0) sb.append(',');
			sb.append('a');
		}
		assertTrue(CITrapReportAPI.shouldRejectFilterTerms(sb.toString(), 64));
	}

	@Test
	public void filterTermsFloodRejected() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 1000; i++) {
			if (i > 0) sb.append(',');
			sb.append('a');
		}
		assertTrue(CITrapReportAPI.shouldRejectFilterTerms(sb.toString(), 64));
	}

	@Test
	public void defaultCapsReasonable() {
		assertTrue(CITrapReportAPI.MAX_CITRAP_REPORT_COUNT >= 50);
		assertTrue(CITrapReportAPI.MAX_CITRAP_REPORT_COUNT <= 100_000);
		assertTrue(CITrapReportAPI.MAX_CITRAP_FILTER_TERMS >= 4);
		assertTrue(CITrapReportAPI.MAX_CITRAP_FILTER_TERMS <= 4096);
	}
}
