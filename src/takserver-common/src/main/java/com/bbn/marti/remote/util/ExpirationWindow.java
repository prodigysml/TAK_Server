package com.bbn.marti.remote.util;

/**
 * Bounds on caller-supplied expiration times (epoch seconds) that end up as scheduled
 * retention tasks. Extreme values churn the scheduler, and seconds * 1000 can overflow.
 */
public final class ExpirationWindow {

	/** Allowed distance from now, either way. Override with -Dtak.mission.maxExpirationWindowSeconds. */
	public static final long DEFAULT_MAX_WINDOW_SECONDS = 10L * 365L * 24L * 3600L;

	private ExpirationWindow() {
	}

	public static long maxWindowSeconds() {
		return Long.getLong("tak.mission.maxExpirationWindowSeconds", DEFAULT_MAX_WINDOW_SECONDS);
	}

	/**
	 * True when {@code expirationSeconds} is acceptable: null or <= 0 (clears the
	 * expiration), or within {@code maxWindowSeconds} of {@code nowSeconds}.
	 */
	public static boolean isAllowed(Long expirationSeconds, long nowSeconds, long maxWindowSeconds) {
		if (expirationSeconds == null || expirationSeconds <= 0) {
			return true;
		}
		return expirationSeconds >= nowSeconds - maxWindowSeconds
				&& expirationSeconds <= nowSeconds + maxWindowSeconds;
	}

	/** {@link #isAllowed(Long, long, long)} against the current time and configured window. */
	public static boolean isAllowed(Long expirationSeconds) {
		return isAllowed(expirationSeconds, System.currentTimeMillis() / 1000L, maxWindowSeconds());
	}

	/**
	 * Epoch seconds to milliseconds.
	 *
	 * @throws IllegalArgumentException if the result does not fit in a long
	 */
	public static long toMillis(long seconds) {
		try {
			return Math.multiplyExact(seconds, 1000L);
		} catch (ArithmeticException e) {
			throw new IllegalArgumentException("expiration out of range: " + seconds);
		}
	}
}
