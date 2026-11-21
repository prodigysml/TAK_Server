package com.bbn.marti.sync.api;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.After;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;
import com.bbn.marti.util.spring.RequestHolderBean;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Stored CoT is returned verbatim, including the free-form &lt;detail&gt; a client wrote,
 * so XML CoT responses must carry a sandbox CSP and nosniff to stop a browser running
 * script embedded in it.
 */
public class CotXmlHeadersTest {

	@After
	public void tearDown() {
		MissionApiTestHarness.tearDown();
	}

	private static void assertHardened(HttpHeaders headers) {
		assertEquals(MediaType.APPLICATION_XML, headers.getContentType());
		assertEquals("nosniff", headers.getFirst("X-Content-Type-Options"));
		assertEquals("default-src 'none'; sandbox", headers.getFirst("Content-Security-Policy"));
	}

	@Test
	public void apply_setsXmlTypeSandboxCspAndNosniff() {
		assertHardened(CotXmlHeaders.apply(new HttpHeaders()));
	}

	@Test
	public void missionCotByGuid_isServedWithHardenedHeaders() throws Exception {
		MissionApiTestHarness h = MissionApiTestHarness.create();
		RequestHolderBean holder = h.inject("requestHolderBean", RequestHolderBean.class);
		when(holder.sessionId()).thenReturn("session");
		CommonUtil util = h.mockField("martiUtil");
		when(util.getGroupVectorBitString(anyString())).thenReturn("1");
		MissionService missionService = h.mockField("missionService");
		Mission mission = mock(Mission.class);
		when(missionService.getMissionByGuidCheckGroups(any(UUID.class), anyString())).thenReturn(mission);
		when(missionService.getCachedCot(any(UUID.class), any(), anyString()))
				.thenReturn("<events><event uid='x'><detail/></event></events>");

		ResponseEntity<String> response = h.api.getLatestMissionCotEventsByGuid(
				UUID.randomUUID().toString(), mock(HttpServletRequest.class));

		assertHardened(response.getHeaders());
	}
}
