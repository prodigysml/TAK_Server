package com.bbn.marti.mfa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.time.Instant;

import org.junit.Test;

public class LoginAttemptServiceTest {

	@Test
	public void initialStateIsUnlocked() {
		LoginAttemptService s = new LoginAttemptService();
		assertFalse(s.isLocked("alice"));
		assertNull(s.lockedUntil("alice"));
	}

	@Test
	public void recordFailureIncrementsCount() {
		LoginAttemptService s = new LoginAttemptService();
		LoginAttemptService.State a = s.recordFailure("bob");
		assertEquals(1, a.count);
		assertNull(a.lockedUntil);
		LoginAttemptService.State b = s.recordFailure("bob");
		assertEquals(2, b.count);
		assertNull(b.lockedUntil);
	}

	@Test
	public void thirdFailureLocksAccount() {
		LoginAttemptService s = new LoginAttemptService();
		s.recordFailure("carol");
		s.recordFailure("carol");
		LoginAttemptService.State third = s.recordFailure("carol");
		assertEquals(3, third.count);
		assertNotNull(third.lockedUntil);
		assertTrue(s.isLocked("carol"));
		assertTrue("lockout must be in the future",
				third.lockedUntil.isAfter(Instant.now()));
		// Within ~30 min of now
		assertTrue("lockout must be within 31 min window",
				third.lockedUntil.isBefore(Instant.now().plusSeconds(31 * 60)));
	}

	@Test
	public void successClearsCounter() {
		LoginAttemptService s = new LoginAttemptService();
		s.recordFailure("dan");
		s.recordFailure("dan");
		s.recordSuccess("dan");
		assertFalse(s.isLocked("dan"));
		LoginAttemptService.State after = s.recordFailure("dan");
		assertEquals("counter should have reset", 1, after.count);
	}

	@Test
	public void perUserIsolation() {
		LoginAttemptService s = new LoginAttemptService();
		s.recordFailure("erin");
		s.recordFailure("erin");
		s.recordFailure("erin");
		assertTrue(s.isLocked("erin"));
		assertFalse("frank should not be locked", s.isLocked("frank"));
	}

	@Test
	public void nullUsernameIsNeverLocked() {
		LoginAttemptService s = new LoginAttemptService();
		assertFalse(s.isLocked(null));
	}
}
