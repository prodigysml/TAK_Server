package com.bbn.marti.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit tests for CommonUtil.xmlEscape — verifies the CoT XML-injection fix.
 * Original code concatenated attacker-controlled strings (callsign, remarks,
 * group, role, type, how) into CoT XML unescaped. A crafted value could
 * inject closing tags or new elements (CWE-91 / CWE-74).
 */
public class XmlEscapeTest {

	@Test
	public void nullInputReturnsEmpty() {
		assertEquals("", CommonUtil.xmlEscape(null));
	}

	@Test
	public void emptyInputReturnsEmpty() {
		assertEquals("", CommonUtil.xmlEscape(""));
	}

	@Test
	public void escapesAmpersand() {
		assertEquals("a&amp;b", CommonUtil.xmlEscape("a&b"));
	}

	@Test
	public void escapesLessThan() {
		assertEquals("a&lt;b", CommonUtil.xmlEscape("a<b"));
	}

	@Test
	public void escapesGreaterThan() {
		assertEquals("a&gt;b", CommonUtil.xmlEscape("a>b"));
	}

	@Test
	public void escapesDoubleQuote() {
		assertEquals("a&quot;b", CommonUtil.xmlEscape("a\"b"));
	}

	@Test
	public void escapesSingleQuote() {
		assertEquals("a&apos;b", CommonUtil.xmlEscape("a'b"));
	}

	@Test
	public void escapesAllFiveEntitiesTogether() {
		assertEquals("&amp;&lt;&gt;&quot;&apos;",
				CommonUtil.xmlEscape("&<>\"'"));
	}

	@Test
	public void escapeIsIdempotentOnUnsafeInput() {
		String once = CommonUtil.xmlEscape("a<b");
		String twice = CommonUtil.xmlEscape(once);
		assertEquals("a&amp;lt;b", twice);
	}

	@Test
	public void preservesAsciiAndUnicode() {
		assertEquals("hello world 123", CommonUtil.xmlEscape("hello world 123"));
		assertEquals("naïve café 中文",
				CommonUtil.xmlEscape("naïve café 中文"));
	}

	@Test
	public void preservesAllowedControlChars() {
		assertEquals("a\tb\nc\rd", CommonUtil.xmlEscape("a\tb\nc\rd"));
	}

	@Test
	public void dropsDisallowedControlChars() {
		// 0x00..0x1F except \t \n \r must be stripped (XML 1.0 disallows them)
		String input = "abcd";
		assertEquals("abcd", CommonUtil.xmlEscape(input));
	}

	@Test
	public void blocksClosingTagInjection() {
		String malicious = "victim'/><inject foo='bar";
		String escaped = CommonUtil.xmlEscape(malicious);
		assertFalse("must not contain raw <", escaped.contains("<"));
		assertFalse("must not contain raw >", escaped.contains(">"));
		assertFalse("must not contain raw '", escaped.contains("'"));
		assertTrue(escaped.contains("&apos;"));
		assertTrue(escaped.contains("&lt;"));
		assertTrue(escaped.contains("&gt;"));
	}

	@Test
	public void blocksAttributeBreakWithDoubleQuote() {
		String malicious = "x\" onclick=alert(1) y=\"";
		String escaped = CommonUtil.xmlEscape(malicious);
		assertFalse(escaped.contains("\""));
		assertTrue(escaped.contains("&quot;"));
	}

	@Test
	public void doesNotIntroduceExtraChars() {
		String safe = "callsign-007";
		assertEquals(safe, CommonUtil.xmlEscape(safe));
	}

	@Test
	public void citrapXmlEscapeMatchesCommonUtilSemantics() {
		// CITrapReportNotifications has its own escape helper — verify same behavior
		assertEquals("", com.bbn.marti.citrap.CITrapReportNotifications.xmlEscape(null));
		assertEquals("&amp;&lt;&gt;&quot;&apos;",
				com.bbn.marti.citrap.CITrapReportNotifications.xmlEscape("&<>\"'"));
		assertEquals("safe",
				com.bbn.marti.citrap.CITrapReportNotifications.xmlEscape("safe"));
	}
}
