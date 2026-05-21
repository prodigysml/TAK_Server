package com.bbn.marti.sync;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.mockito.Mockito;

import com.bbn.marti.sync.api.MissionApi;

/**
 * Verifies resolveSafeServerBaseUrl does not propagate the caller's Host
 * header. Previously sendMissionArchive embedded request.getRequestURL() in
 * the outgoing CoT fileshare message; an attacker who could set Host:
 * evil.com could redirect TAK clients to attacker-controlled hosts
 * (CWE-601). Also exercises the contacts-list cap.
 */
public class MissionApiServerBaseUrlTest {

	@Test
	public void usesLocalNameOverHostHeader() {
		HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
		Mockito.when(req.getServerName()).thenReturn("evil.example.com");
		Mockito.when(req.getLocalName()).thenReturn("tak-internal");
		Mockito.when(req.getLocalAddr()).thenReturn("10.0.0.1");
		Mockito.when(req.getLocalPort()).thenReturn(8443);
		Mockito.when(req.getScheme()).thenReturn("https");

		// Pass null configured host -> exercise the local-interface fallback.
		String base = MissionApi.buildSafeServerBaseUrl(req, null);
		assertFalse("Host header leaked into base URL: " + base,
				base.contains("evil.example.com"));
		assertTrue("base url missing local interface: " + base,
				base.contains("tak-internal") || base.contains("10.0.0.1"));
	}

	@Test
	public void schemeAndPortRespected() {
		HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
		Mockito.when(req.getLocalName()).thenReturn("server.local");
		Mockito.when(req.getLocalAddr()).thenReturn("10.0.0.1");
		Mockito.when(req.getLocalPort()).thenReturn(9443);
		Mockito.when(req.getScheme()).thenReturn("https");

		String base = MissionApi.buildSafeServerBaseUrl(req, null);
		assertTrue(base.startsWith("https://"));
		assertTrue("non-default port should be embedded: " + base,
				base.endsWith(":9443"));
	}

	@Test
	public void defaultHttpsPortOmitted() {
		HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
		Mockito.when(req.getLocalName()).thenReturn("server.local");
		Mockito.when(req.getLocalAddr()).thenReturn("10.0.0.1");
		Mockito.when(req.getLocalPort()).thenReturn(443);
		Mockito.when(req.getScheme()).thenReturn("https");

		String base = MissionApi.buildSafeServerBaseUrl(req, null);
		assertFalse("default https port should be omitted: " + base,
				base.contains(":443"));
	}

	@Test
	public void configuredHostUsedWhenPresent() {
		HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
		Mockito.when(req.getLocalName()).thenReturn("ignored");
		Mockito.when(req.getLocalAddr()).thenReturn("10.0.0.1");
		Mockito.when(req.getLocalPort()).thenReturn(8443);
		Mockito.when(req.getScheme()).thenReturn("https");

		String base = MissionApi.buildSafeServerBaseUrl(req, "tak.example.com");
		assertTrue(base.startsWith("https://tak.example.com"));
		assertFalse("local interface should not leak when configured host set: " + base,
				base.contains("ignored"));
	}

	@Test
	public void contactsCapBoundary() {
		assertFalse(MissionApi.shouldRejectListSize(0, MissionApi.MAX_SEND_CONTACT_UIDS));
		assertFalse(MissionApi.shouldRejectListSize(
				MissionApi.MAX_SEND_CONTACT_UIDS,
				MissionApi.MAX_SEND_CONTACT_UIDS));
		assertTrue(MissionApi.shouldRejectListSize(
				MissionApi.MAX_SEND_CONTACT_UIDS + 1,
				MissionApi.MAX_SEND_CONTACT_UIDS));
	}

	@Test
	public void contactsCapIsReasonable() {
		assertTrue(MissionApi.MAX_SEND_CONTACT_UIDS >= 16);
		assertTrue(MissionApi.MAX_SEND_CONTACT_UIDS <= 10_000);
	}
}
