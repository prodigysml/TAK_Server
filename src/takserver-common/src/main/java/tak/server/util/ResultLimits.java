package tak.server.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Helpers for bounding result-set sizes on admin/operator list endpoints to
 * prevent unbounded in-memory collection, sorting, and serialization when the
 * backing table grows pathologically large (CWE-400/770).
 *
 * <p>These bounds are deliberately generous: they sit far above any realistic
 * deployment count, so normal admin listing is unaffected. Callers should log
 * when {@link #exceedsCap} is true so a truncation is observable rather than
 * silent. This must only be applied to admin/web-UI endpoints, never to the
 * mission-sync / CoT / enterprise-sync endpoints consumed by ATAK/iTAK clients.
 */
public final class ResultLimits {

	private ResultLimits() {
	}

	/** @return true if a result of {@code size} would be truncated by {@code maxResults} (maxResults &lt;= 0 means no cap). */
	public static boolean exceedsCap(int size, int maxResults) {
		return maxResults > 0 && size > maxResults;
	}

	/**
	 * Returns at most {@code maxResults} elements from {@code src} in iteration order.
	 * Returns a copy of all elements when within the cap, an empty list for null input,
	 * and all elements when {@code maxResults <= 0} (no cap).
	 */
	public static <T> List<T> bounded(Collection<? extends T> src, int maxResults) {
		List<T> out = new ArrayList<>();
		if (src == null) {
			return out;
		}
		if (maxResults <= 0 || src.size() <= maxResults) {
			out.addAll(src);
			return out;
		}
		for (T element : src) {
			if (out.size() >= maxResults) {
				break;
			}
			out.add(element);
		}
		return out;
	}
}
