package tak.server.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.regex.Pattern;

import org.junit.Test;

public class SqlRegexUtilsTest {

	@Test
	public void nullReturnsNull() {
		assertNull(SqlRegexUtils.escapePosixEre(null));
	}

	@Test
	public void plainIdentifierUnchanged() {
		// Typical CoT uids / hashes contain no ERE metacharacters.
		assertEquals("ANDROID-123_abc", SqlRegexUtils.escapePosixEre("ANDROID-123_abc"));
		assertEquals("a1b2c3d4e5", SqlRegexUtils.escapePosixEre("a1b2c3d4e5"));
	}

	@Test
	public void broadMatchPatternIsNeutralized() {
		assertEquals("\\.\\*", SqlRegexUtils.escapePosixEre(".*"));
		assertEquals("\\.\\+", SqlRegexUtils.escapePosixEre(".+"));
	}

	@Test
	public void catastrophicPatternIsNeutralized() {
		assertEquals("\\(a\\+\\)\\+", SqlRegexUtils.escapePosixEre("(a+)+"));
	}

	@Test
	public void dotMatchesLiterallyAfterEscaping() {
		String escaped = SqlRegexUtils.escapePosixEre("abc.def");
		assertEquals("abc\\.def", escaped);
		// The escaped form, used as a Java regex, matches the literal but not an arbitrary char.
		assertTrue(Pattern.compile(escaped).matcher("abc.def").find());
		org.junit.Assert.assertFalse(Pattern.compile(escaped).matcher("abcXdef").find());
	}

	@Test
	public void backslashIsEscaped() {
		assertEquals("a\\\\b", SqlRegexUtils.escapePosixEre("a\\b"));
	}
}
