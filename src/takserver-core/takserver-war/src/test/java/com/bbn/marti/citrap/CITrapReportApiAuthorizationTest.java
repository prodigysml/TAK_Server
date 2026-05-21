package com.bbn.marti.citrap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Verifies CITrapReportAPI.deleteReport carries @PreAuthorize ROLE_ADMIN.
 * Without it, any non-admin UI user could supply an arbitrary clientUid
 * and delete CI-TRAP reports for which they are not the owner — the
 * service layer authorizes only on group membership.
 */
public class CITrapReportApiAuthorizationTest {

	private static final String EXPECTED = "hasRole('ROLE_ADMIN')";

	@Test
	public void deleteReportRequiresAdmin() throws Exception {
		Method found = null;
		for (Method m : CITrapReportAPI.class.getDeclaredMethods()) {
			if (m.getName().equals("deleteReport")) {
				if (found != null) {
					throw new IllegalStateException("ambiguous deleteReport overload");
				}
				found = m;
			}
		}
		assertNotNull("deleteReport method not found", found);

		PreAuthorize ann = found.getAnnotation(PreAuthorize.class);
		assertNotNull("missing @PreAuthorize on deleteReport", ann);
		assertEquals(EXPECTED, ann.value());
	}
}
