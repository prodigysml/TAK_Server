package com.bbn.marti.sync;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Verifies @PreAuthorize("hasRole('ROLE_ADMIN')") is wired on every
 * MetadataApi PUT endpoint. None of these URLs has a matching
 * intercept-url rule in security-context.xml, so the annotation is the
 * only authorization gate. Drift = silent IDOR regression.
 */
public class MetadataApiAuthorizationTest {

	private static final String EXPECTED = "hasRole('ROLE_ADMIN')";

	private Method findUnique(String name) throws NoSuchMethodException {
		Method found = null;
		for (Method m : MetadataApi.class.getDeclaredMethods()) {
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
	public void setMetadataRequiresAdmin() throws Exception {
		assertAdminOnly("setMetadata");
	}

	@Test
	public void setMetadataKeywordsRequiresAdmin() throws Exception {
		assertAdminOnly("setMetadataKeywords");
	}

	@Test
	public void setExpirationRequiresAdmin() throws Exception {
		assertAdminOnly("setExpiration");
	}
}
