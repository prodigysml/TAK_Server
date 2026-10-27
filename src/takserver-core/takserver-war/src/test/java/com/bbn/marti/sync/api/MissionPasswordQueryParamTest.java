package com.bbn.marti.sync.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import com.bbn.marti.config.Configuration;
import com.bbn.marti.config.Network;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.repository.MissionRepository;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;

/**
 * Tests that {@link MissionApi} reads the mission password from the 'password'
 * query parameter as well as the MissionPassword header.
 *
 * <p>ATAK, iTAK, WinTAK and the admin UI only send the query parameter. When the
 * API read the header alone, every password those clients sent was dropped:
 * missions were created without one, and joining a protected mission failed.
 */
public class MissionPasswordQueryParamTest {

	private MissionApiTestHarness harness;
	private MissionApi api;
	private MissionService missionService;
	private MissionRepository missionRepository;
	private HttpServletRequest request;

	private final String name = "mission-1";
	private final String gv = "groupvector";

	@Before
	public void setUp() {
		harness = MissionApiTestHarness.create();
		api = harness.api;
		missionService = harness.mockField("missionService");
		missionRepository = harness.mockField("missionRepository");
		CommonUtil martiUtil = harness.mockField("martiUtil");
		request = org.mockito.Mockito.mock(HttpServletRequest.class);

		when(missionService.trimName(name)).thenReturn(name);
		when(martiUtil.getGroupVectorBitString(request)).thenReturn(gv);

		Network network = new Network();
		network.setMissionRequiresPassword(true);
		Configuration configuration = new Configuration();
		configuration.setNetwork(network);
		CoreConfigFacade.setInstanceForTesting(configuration);
	}

	@After
	public void tearDown() {
		MissionApiTestHarness.tearDown();
	}

	@Test
	public void missionPassword_prefersHeaderThenQueryParam() {
		assertEquals("header", MissionApi.missionPassword("header", "query"));
		assertEquals("query", MissionApi.missionPassword(null, "query"));
		assertEquals("query", MissionApi.missionPassword("", "query"));
		assertEquals("", MissionApi.missionPassword(null, null));
	}

	@Test
	public void setPassword_withQueryParamOnly_storesThatPassword() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		when(mission.getGuid()).thenReturn("11111111-1111-1111-1111-111111111111");
		when(mission.getGroupVector()).thenReturn(gv);
		when(mission.getTool()).thenReturn("public");
		when(missionService.getMission(name, gv)).thenReturn(mission);
		when(missionRepository.setPasswordHash(eq(name), anyString(), eq(gv))).thenReturn(42L);

		api.setPassword(name, null, "fromQuery", "creator", request);

		ArgumentCaptor<String> hash = ArgumentCaptor.forClass(String.class);
		verify(missionRepository).setPasswordHash(eq(name), hash.capture(), eq(gv));
		assertTrue(BCrypt.checkpw("fromQuery", hash.getValue()));
	}

	/**
	 * Every endpoint that takes the MissionPassword header must also take the
	 * 'password' query parameter, so a new or changed endpoint can't drop it again.
	 */
	@Test
	public void everyMissionPasswordHeader_hasPasswordQueryParam() {
		List<String> missing = new ArrayList<>();
		int endpoints = 0;
		for (Method m : MissionApi.class.getDeclaredMethods()) {
			boolean header = false;
			boolean query = false;
			for (Parameter p : m.getParameters()) {
				for (Annotation a : p.getAnnotations()) {
					if (a instanceof RequestHeader && "MissionPassword".equals(((RequestHeader) a).value())) {
						header = true;
					}
					if (a instanceof RequestParam && "password".equals(((RequestParam) a).value())) {
						query = true;
					}
				}
			}
			if (header) {
				endpoints++;
				if (!query) {
					missing.add(m.getName());
				}
			}
		}
		assertEquals(10, endpoints);
		assertTrue("no 'password' query parameter on: " + missing, missing.isEmpty());
	}
}
