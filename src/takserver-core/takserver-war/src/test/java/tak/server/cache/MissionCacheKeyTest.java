package tak.server.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit tests for MissionCacheHelper.getKey — verifies cache key is
 * group-vector-scoped (CWE-639 IDOR via cache reuse). Original key did not
 * include groupVector, so a low-priv user could be served a Mission record
 * cached for a higher-priv user.
 */
public class MissionCacheKeyTest {

	@Test
	public void sameNameDifferentGroupVectorYieldsDifferentKey() {
		String a = MissionCacheHelper.getKey("op-alpha", true, "GROUP_A");
		String b = MissionCacheHelper.getKey("op-alpha", true, "GROUP_B");
		assertNotEquals("group vector must influence cache key", a, b);
	}

	@Test
	public void sameNameSameVectorYieldsSameKey() {
		String a = MissionCacheHelper.getKey("op-alpha", true, "GROUP_A");
		String b = MissionCacheHelper.getKey("op-alpha", true, "GROUP_A");
		assertEquals(a, b);
	}

	@Test
	public void differentHydrateFlagsYieldDifferentKey() {
		String a = MissionCacheHelper.getKey("op-alpha", true, "GROUP_A");
		String b = MissionCacheHelper.getKey("op-alpha", false, "GROUP_A");
		assertNotEquals(a, b);
	}

	@Test
	public void missionNameLowercased() {
		// case-insensitive collapse — different case but same logical mission
		String a = MissionCacheHelper.getKey("OP-Alpha", true, "G");
		String b = MissionCacheHelper.getKey("op-alpha", true, "G");
		assertEquals(a, b);
	}

	@Test
	public void nullGroupVectorIsAcceptedAndDistinctFromEmpty() {
		// legacy two-arg form (no group vector) used by background work
		String legacy = MissionCacheHelper.getKey("op-alpha", true);
		String withGv = MissionCacheHelper.getKey("op-alpha", true, "G");
		assertNotEquals("legacy null-vector key must not collide with any real vector",
				legacy, withGv);
	}

	@Test
	public void keyContainsMissionNameAndVector() {
		String k = MissionCacheHelper.getKey("op-alpha", true, "GROUP_X");
		assertTrue("key should contain mission name", k.contains("op-alpha"));
		assertTrue("key should contain group vector", k.contains("GROUP_X"));
	}

	@Test
	public void differentMissionsNeverCollide() {
		String a = MissionCacheHelper.getKey("op-alpha", true, "G");
		String b = MissionCacheHelper.getKey("op-bravo", true, "G");
		assertNotEquals(a, b);
	}

	@Test
	public void overlappingNamesDoNotCollideByPrefix() {
		// regression: "alpha" vs "alpha2" must not produce same key under any
		// flag/vector combination via accidental string concatenation
		String a = MissionCacheHelper.getKey("alpha", true, "G");
		String b = MissionCacheHelper.getKey("alpha2", true, "G");
		assertFalse(a.equals(b));
	}
}
