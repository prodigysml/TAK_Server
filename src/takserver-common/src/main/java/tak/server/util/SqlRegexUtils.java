package tak.server.util;

/**
 * Helpers for safely using request-supplied values inside SQL POSIX regex
 * predicates (PostgreSQL {@code ~}).
 *
 * <p>Binding a raw user value as a regex lets a caller pass a broad pattern
 * (e.g. {@code .*}) that matches every row, or a catastrophic-backtracking
 * pattern that pins the regex engine — a CPU/DoS and ReDoS vector
 * (CWE-400/CWE-1333). Escaping the value so it is matched literally keeps the
 * existing (unanchored, substring) match behavior for legitimate identifiers
 * while neutralizing metacharacters.
 */
public final class SqlRegexUtils {

	private SqlRegexUtils() {
	}

	// POSIX ERE metacharacters. Backslash is included and handled first by virtue of being
	// in the set: each occurrence is individually prefixed with a backslash.
	private static final String ERE_METACHARACTERS = "\\.^$|?*+()[]{}";

	/**
	 * Escapes POSIX ERE metacharacters in {@code input} so it is matched literally by a
	 * SQL {@code ~} predicate. Returns null for null input.
	 */
	public static String escapePosixEre(String input) {
		if (input == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder(input.length() + 8);
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (ERE_METACHARACTERS.indexOf(c) >= 0) {
				sb.append('\\');
			}
			sb.append(c);
		}
		return sb.toString();
	}
}
