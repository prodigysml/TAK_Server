package com.bbn.marti.network;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Pin @PreAuthorize on SecurityAuthenticationApi config endpoints. The GET
 * fans out to every cluster node via MessagingIgniteBroker (parallelStream
 * with no per-call cap), so it must be operator-only to prevent
 * any-authenticated cluster amplification (CWE-400, CWE-770). The PUT
 * mutates auth provider config and must also be admin-only.
 */
public class SecurityAuthenticationApiAuthorizationTest {

	private static final String EXPECTED = "hasRole('ROLE_ADMIN')";

	private Method find(String name) {
		for (Method m : SecurityAuthenticationApi.class.getDeclaredMethods()) {
			if (m.getName().equals(name)) return m;
		}
		throw new IllegalStateException("missing: " + name);
	}

	private void assertAdminOnly(String name) {
		Method m = find(name);
		PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
		assertNotNull("missing @PreAuthorize on " + name, ann);
		assertEquals(EXPECTED, ann.value());
	}

	@Test
	public void getAuthConfigRequiresAdmin() {
		assertAdminOnly("getAuthConfig");
	}

	@Test
	public void modifyAuthConfigRequiresAdmin() {
		assertAdminOnly("modifyAuthConfig");
	}
}
