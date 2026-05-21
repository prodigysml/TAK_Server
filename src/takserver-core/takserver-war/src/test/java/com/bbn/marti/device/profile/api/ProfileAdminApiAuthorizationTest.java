package com.bbn.marti.device.profile.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * POST /device/profile/{name}/send distributes a profile mission package
 * to caller-supplied contact UIDs. Without an admin gate, any
 * authenticated user could trigger server-side distribution of any
 * profile to any contact. The intercept-url rules in
 * security-context.xml carve out anonymous read access for
 * /device/profile/tool/** but do not restrict POST on this path; the
 * @PreAuthorize annotation is the load-bearing gate.
 */
public class ProfileAdminApiAuthorizationTest {

	@Test
	public void sendProfileRequiresAdmin() throws Exception {
		Method found = null;
		for (Method m : ProfileAdminAPI.class.getDeclaredMethods()) {
			if (m.getName().equals("sendProfile")) {
				if (found != null) throw new IllegalStateException("ambiguous sendProfile overload");
				found = m;
			}
		}
		assertNotNull("sendProfile not found", found);
		PreAuthorize ann = found.getAnnotation(PreAuthorize.class);
		assertNotNull("missing @PreAuthorize on sendProfile", ann);
		assertEquals("hasRole('ROLE_ADMIN')", ann.value());
	}
}
