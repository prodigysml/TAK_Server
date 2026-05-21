package com.bbn.marti.device.profile.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Verifies the group-name list size cap used by ProfileAdminAPI.createProfile
 * and updateProfile, and the @PreAuthorize wiring on those mutators. Each
 * group name triggers groupManager.findGroups + bit-vector assembly, so an
 * unbounded list is a DoS primitive (CWE-400). Both mutators also need admin
 * gating since security-context.xml only pins DELETE and /send POST.
 */
public class ProfileAdminAPIGroupCapTest {

	private static final String EXPECTED = "hasRole('ROLE_ADMIN')";

	private Method find(String name) {
		for (Method m : ProfileAdminAPI.class.getDeclaredMethods()) {
			if (m.getName().equals(name)) return m;
		}
		throw new IllegalStateException("missing: " + name);
	}

	private void assertAdminOnly(String name) {
		Method m = find(name);
		PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
		assertNotNull("missing @PreAuthorize on " + name, ann);
		assertEquals("wrong expr on " + name, EXPECTED, ann.value());
	}

	@Test
	public void zeroIsAccepted() {
		assertFalse(ProfileAdminAPI.shouldRejectGroupList(0, 256));
	}

	@Test
	public void atCapAccepted() {
		assertFalse(ProfileAdminAPI.shouldRejectGroupList(256, 256));
	}

	@Test
	public void oneOverRejected() {
		assertTrue(ProfileAdminAPI.shouldRejectGroupList(257, 256));
	}

	@Test
	public void largeFloodRejected() {
		assertTrue(ProfileAdminAPI.shouldRejectGroupList(1_000_000, 256));
	}

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(ProfileAdminAPI.MAX_PROFILE_GROUP_NAMES >= 16);
		assertTrue(ProfileAdminAPI.MAX_PROFILE_GROUP_NAMES <= 4096);
	}

	@Test
	public void createProfileRequiresAdmin() {
		assertAdminOnly("createProfile");
	}

	@Test
	public void updateProfileRequiresAdmin() {
		assertAdminOnly("updateProfile");
	}
}
