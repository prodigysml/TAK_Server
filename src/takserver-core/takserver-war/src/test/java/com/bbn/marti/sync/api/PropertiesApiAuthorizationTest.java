package com.bbn.marti.sync.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * GET /properties/uids enumerates every UID with stored properties — a
 * recon primitive that should not be accessible to ordinary
 * authenticated users. The /properties/** wildcard is ROLE_ANONYMOUS
 * for GET (line 226 of security-context.xml); the listing endpoint
 * must override that with admin-only access.
 */
public class PropertiesApiAuthorizationTest {

	@Test
	public void getAllPropertyKeysRequiresAdmin() throws Exception {
		Method m = PropertiesApi.class.getDeclaredMethod("getAllPropertyKeys");
		PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
		assertNotNull("missing @PreAuthorize on getAllPropertyKeys", ann);
		assertEquals("hasRole('ROLE_ADMIN')", ann.value());
	}
}
