package com.bbn.marti.citrap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

/**
 * Unit tests for CITrapReportNotifications.xmlEscape — verifies the CoT
 * XML-injection fix on the CI-TRAP notification path. Same semantics as
 * CommonUtil.xmlEscape; this test guards the duplicate implementation
 * against drift.
 */
public class CITrapXmlEscapeTest {

	@Test
	public void nullReturnsEmpty() {
		assertEquals("", CITrapReportNotifications.xmlEscape(null));
	}

	@Test
	public void escapesAllFiveEntities() {
		assertEquals("&amp;&lt;&gt;&quot;&apos;",
				CITrapReportNotifications.xmlEscape("&<>\"'"));
	}

	@Test
	public void passesSafeStringThrough() {
		assertEquals("safe-callsign-007",
				CITrapReportNotifications.xmlEscape("safe-callsign-007"));
	}

	@Test
	public void blocksClosingTagInjection() {
		String escaped = CITrapReportNotifications.xmlEscape("x'/><foo");
		assertFalse(escaped.contains("<"));
		assertFalse(escaped.contains(">"));
		assertFalse(escaped.contains("'"));
	}
}
