package com.bbn.marti.network;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Verifies @PreAuthorize("hasRole('ROLE_ADMIN')") is wired on FederationApi
 * endpoints that lack a matching intercept-url rule in security-context.xml.
 * Defense in depth: if the XML rule is later edited away or the URL prefix
 * shifts, the annotation still enforces admin-only access.
 */
public class FederationApiAuthorizationTest {

	private static final String EXPECTED = "hasRole('ROLE_ADMIN')";

	private Method findUnique(String name) throws NoSuchMethodException {
		Method found = null;
		for (Method m : FederationApi.class.getDeclaredMethods()) {
			if (m.getName().equals(name)) {
				if (found != null) {
					throw new IllegalStateException("ambiguous method name: " + name);
				}
				found = m;
			}
		}
		if (found == null) throw new NoSuchMethodException(name);
		return found;
	}

	private void assertAdminOnly(String methodName) throws Exception {
		Method m = findUnique(methodName);
		PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
		assertNotNull("missing @PreAuthorize on " + methodName, ann);
		assertEquals("wrong access expression on " + methodName,
				EXPECTED, ann.value());
	}

	@Test
	public void updateFederateMissionsRequiresAdmin() throws Exception {
		assertAdminOnly("updateFederateMissions");
	}

	@Test
	public void getFederateRemoteGroupsRequiresAdmin() throws Exception {
		assertAdminOnly("getFederateRemoteGroups");
	}

	@Test
	public void setFederateCAHopsRequiresAdmin() throws Exception {
		assertAdminOnly("setFederateCAHops");
	}

	@Test
	public void getNumRequiresAdmin() throws Exception {
		assertAdminOnly("getNum");
	}

	@Test
	public void preAuthorizeExpressionIsLiteralAdminRole() throws Exception {
		// Guard against accidental loosening to e.g. permitAll(), isAuthenticated(),
		// or hasAnyRole(...). Only the exact admin expression is acceptable.
		for (String name : new String[]{
				"updateFederateMissions",
				"getFederateRemoteGroups",
				"setFederateCAHops",
				"getNum"}) {
			Method m = findUnique(name);
			PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
			assertTrue("non-admin expression on " + name + ": " + ann.value(),
					ann.value().contains("ROLE_ADMIN"));
		}
	}
}
