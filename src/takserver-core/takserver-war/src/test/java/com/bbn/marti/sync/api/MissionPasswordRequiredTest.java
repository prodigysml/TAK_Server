package com.bbn.marti.sync.api;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.config.Configuration;
import com.bbn.marti.config.Network;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.bbn.marti.remote.exception.ForbiddenException;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.repository.MissionRepository;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;

/**
 * Tests for the MissionRequiresPassword network setting in {@link MissionApi}.
 *
 * <p>When it is on, missions created or copied through the API must carry a
 * password, and a password can be changed but not removed or set to empty.
 * When it is off (the default), the stock optional-password behaviour holds.
 */
public class MissionPasswordRequiredTest {

	private static final String GUID = "11111111-1111-1111-1111-111111111111";

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
	}

	@After
	public void tearDown() {
		MissionApiTestHarness.tearDown();
	}

	private void setMissionRequiresPassword(boolean required) {
		Network network = new Network();
		network.setMissionRequiresPassword(required);
		Configuration configuration = new Configuration();
		configuration.setNetwork(network);
		CoreConfigFacade.setInstanceForTesting(configuration);
	}

	private Mission stubMission() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		when(mission.getGuid()).thenReturn(GUID);
		when(mission.getGroupVector()).thenReturn(gv);
		when(mission.getTool()).thenReturn("public");
		return mission;
	}

	@Test
	public void removePassword_whenRequired_isForbiddenAndLeavesHashAlone() {
		setMissionRequiresPassword(true);

		try {
			api.removePassword(name, "creator", request);
			fail("expected ForbiddenException when mission passwords are required");
		} catch (ForbiddenException expected) {
			// pass
		}

		verify(missionRepository, never()).setPasswordHash(anyString(), any(), anyString());
	}

	@Test
	public void removePasswordByGuid_whenRequired_isForbiddenAndLeavesHashAlone() {
		setMissionRequiresPassword(true);

		try {
			api.removePasswordByGuid(GUID, "creator", request);
			fail("expected ForbiddenException when mission passwords are required");
		} catch (ForbiddenException expected) {
			// pass
		}

		verify(missionRepository, never()).setPasswordHashByGuid(anyString(), any(), anyString());
	}

	@Test
	public void removePassword_whenNotRequired_clearsHash() {
		setMissionRequiresPassword(false);
		Mission mission = stubMission();
		when(missionService.getMission(name, gv)).thenReturn(mission);
		when(missionRepository.setPasswordHash(name, null, gv)).thenReturn(42L);

		api.removePassword(name, "creator", request);

		verify(missionRepository).setPasswordHash(name, null, gv);
	}

	@Test
	public void setPassword_whenRequired_rejectsEmptyPassword() {
		setMissionRequiresPassword(true);

		try {
			api.setPassword(name, "", "creator", request);
			fail("expected IllegalArgumentException for an empty password");
		} catch (IllegalArgumentException expected) {
			// pass
		}

		verify(missionRepository, never()).setPasswordHash(anyString(), any(), anyString());
	}

	@Test
	public void setPassword_whenRequired_acceptsNewPassword() {
		setMissionRequiresPassword(true);
		Mission mission = stubMission();
		when(missionService.getMission(name, gv)).thenReturn(mission);
		when(missionRepository.setPasswordHash(eq(name), anyString(), eq(gv))).thenReturn(42L);

		api.setPassword(name, "secret", "creator", request);

		verify(missionRepository).setPasswordHash(eq(name), anyString(), eq(gv));
	}

	@Test
	public void copyMission_whenRequired_rejectsMissingPassword() {
		setMissionRequiresPassword(true);

		try {
			api.copyMission(name, "creator", "copy-1", null, null, null);
			fail("expected IllegalArgumentException when copying without a password");
		} catch (IllegalArgumentException expected) {
			assertTrue(expected.getMessage().contains("password is required"));
		}
	}

	@Test
	public void createMission_whenRequired_rejectsMissingPasswordBeforeCreating() throws Exception {
		setMissionRequiresPassword(true);

		Method create = null;
		for (Method m : MissionApi.class.getDeclaredMethods()) {
			if (m.getName().equals("doInternalCreateMission")) {
				create = m;
			}
		}
		create.setAccessible(true);

		// every argument null: no password, and nothing else is reached before the check
		Object[] args = new Object[create.getParameterCount()];
		try {
			create.invoke(api, args);
			fail("expected IllegalArgumentException when creating without a password");
		} catch (InvocationTargetException e) {
			assertTrue(e.getCause() instanceof IllegalArgumentException);
		}

		verifyNoInteractions(missionService);
	}
}
