package com.bbn.marti.mfa;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Per-user lockout counter shared by password login and TOTP verify.
 *
 * Three failed attempts within the lockout window lock the user out for
 * 30 minutes. State is in-process and resets on container restart, which
 * is acceptable because each Sydney task is a single ECS Fargate node;
 * there is no horizontal scale-out to worry about.
 *
 * A successful authentication clears the counter for that user. The
 * username key matches the value stored in user_totp_secret.username and
 * UserAuthenticationFile.xml, so the same record covers both factors.
 */
public class LoginAttemptService {

	private static final Logger logger = LoggerFactory.getLogger(LoginAttemptService.class);

	public static final int MAX_ATTEMPTS = 3;
	public static final Duration LOCK_DURATION = Duration.ofMinutes(30);

	private final ConcurrentMap<String, AtomicReference<State>> table = new ConcurrentHashMap<>();

	public boolean isLocked(String username) {
		if (username == null) return false;
		AtomicReference<State> ref = table.get(username);
		if (ref == null) return false;
		State s = ref.get();
		return s != null && s.lockedUntil != null && Instant.now().isBefore(s.lockedUntil);
	}

	public Instant lockedUntil(String username) {
		AtomicReference<State> ref = table.get(username);
		return ref == null ? null : (ref.get() == null ? null : ref.get().lockedUntil);
	}

	/**
	 * Record a failed attempt. Returns the post-update state so the caller
	 * can decide between "wrong code" and "you are now locked out".
	 */
	public State recordFailure(String username) {
		AtomicReference<State> ref = table.computeIfAbsent(
				username, k -> new AtomicReference<>(new State(0, null)));
		State updated;
		while (true) {
			State current = ref.get();
			int count = current.count + 1;
			Instant locked = current.lockedUntil;
			if (count >= MAX_ATTEMPTS) {
				locked = Instant.now().plus(LOCK_DURATION);
			}
			updated = new State(count, locked);
			if (ref.compareAndSet(current, updated)) {
				break;
			}
		}
		if (updated.lockedUntil != null) {
			logger.warn("login lockout user={} attempts={} until={}",
					username, updated.count, updated.lockedUntil);
		}
		return updated;
	}

	public void recordSuccess(String username) {
		if (username == null) return;
		table.remove(username);
	}

	public static final class State {
		public final int count;
		public final Instant lockedUntil;
		public State(int count, Instant lockedUntil) {
			this.count = count;
			this.lockedUntil = lockedUntil;
		}
	}
}
