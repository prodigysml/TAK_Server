package tak.server.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Tests for {@link UsernameUtils#isProtectedAdmin}, the single source of truth
 * for which account the user-management and onboarding flows must never remove.
 */
public class UsernameUtilsTest {

	@Test
	public void protectedAdmin_matchesExactName() {
		assertTrue(UsernameUtils.isProtectedAdmin("takadmin"));
	}

	@Test
	public void protectedAdmin_isCaseInsensitive() {
		assertTrue(UsernameUtils.isProtectedAdmin("TakAdmin"));
		assertTrue(UsernameUtils.isProtectedAdmin("TAKADMIN"));
	}

	@Test
	public void protectedAdmin_ignoresSurroundingWhitespace() {
		assertTrue(UsernameUtils.isProtectedAdmin("  takadmin  "));
	}

	@Test
	public void protectedAdmin_rejectsLookalikes() {
		assertFalse(UsernameUtils.isProtectedAdmin("takadmin2"));
		assertFalse(UsernameUtils.isProtectedAdmin("takadmi"));
		assertFalse(UsernameUtils.isProtectedAdmin("admin"));
		assertFalse(UsernameUtils.isProtectedAdmin("xtakadmin"));
	}

	@Test
	public void protectedAdmin_handlesNull() {
		assertFalse(UsernameUtils.isProtectedAdmin(null));
	}

	@Test
	public void protectedAdmin_constantIsTakadmin() {
		assertEquals("takadmin", UsernameUtils.PROTECTED_ADMIN_USERNAME);
	}
}
