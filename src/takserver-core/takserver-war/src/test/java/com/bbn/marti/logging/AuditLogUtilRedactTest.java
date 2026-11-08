package com.bbn.marti.logging;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * AuditLogUtil.setMdc copies every request/response header into the MDC, which
 * the audit JSON layout writes out. Credential headers must be redacted.
 */
public class AuditLogUtilRedactTest {

	@Test
	public void credentialHeadersAreRedacted() {
		assertEquals("[REDACTED]", AuditLogUtil.redactHeader("Authorization", "Basic dXNlcjpwYXNz"));
		assertEquals("[REDACTED]", AuditLogUtil.redactHeader("authorization", "Bearer eyJ..."));
		assertEquals("[REDACTED]", AuditLogUtil.redactHeader("Cookie", "access_token=eyJ..."));
		assertEquals("[REDACTED]", AuditLogUtil.redactHeader("Set-Cookie", "access_token=eyJ..."));
		assertEquals("[REDACTED]", AuditLogUtil.redactHeader("Proxy-Authorization", "Basic x"));
		assertEquals("[REDACTED]", AuditLogUtil.redactHeader("X-Keystore-Password", "secret"));
	}

	@Test
	public void otherHeadersAreKept() {
		assertEquals("ATAK", AuditLogUtil.redactHeader("User-Agent", "ATAK"));
		assertEquals(null, AuditLogUtil.redactHeader("Accept", null));
	}
}
