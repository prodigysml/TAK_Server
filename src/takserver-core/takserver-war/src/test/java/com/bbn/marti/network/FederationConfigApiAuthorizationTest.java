package com.bbn.marti.network;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Pin @PreAuthorize on FederationConfigApi. PUT /federationconfig writes
 * federation settings and triggers a distributed reconfigureFederation()
 * call across cluster nodes; GETs leak operator-grade federation
 * configuration. /federationconfig had no intercept-url rule in
 * security-context.xml and previously fell through to the default
 * authenticated rule -- any logged-in caller could disrupt federation.
 */
public class FederationConfigApiAuthorizationTest {

	private static final String EXPECTED = "hasRole('ROLE_ADMIN')";

	private Method find(String name) {
		for (Method m : FederationConfigApi.class.getDeclaredMethods()) {
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
	public void getFederationConfigRequiresAdmin() {
		assertAdminOnly("getFederationConfig");
	}

	@Test
	public void modifyFederationConfigRequiresAdmin() {
		assertAdminOnly("modifyFederationConfig");
	}

	@Test
	public void verifyFederationTruststoreRequiresAdmin() {
		assertAdminOnly("verifyFederationTruststore");
	}
}
