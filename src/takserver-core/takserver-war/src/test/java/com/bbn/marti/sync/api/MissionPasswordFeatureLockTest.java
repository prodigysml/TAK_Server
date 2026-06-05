package com.bbn.marti.sync.api;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.remote.exception.NotFoundException;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.repository.MissionRepository;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;

/**
 * Tests for the mission-password endpoints in {@link MissionApi} (ZeroPath
 * cluster #5, issues 6bc44c3d / fab15ebd, CWE-252/367/682).
 *
 * <p>setPassword runs a group-scoped conditional UPDATE ({@code returning id})
 * after getMission validated the mission. The id was ignored, so a row removed
 * or moved out of the caller's groups between the check and the update (TOCTOU)
 * still invalidated the cache and broadcast a password change that never
 * happened. The endpoints now throw NotFoundException and do neither when the
 * UPDATE matches no row.
 */
public class MissionPasswordFeatureLockTest {

	private MissionApiTestHarness harness;
	private MissionApi api;
	private MissionService missionService;
	private MissionRepository missionRepository;
	private SubscriptionManagerLite subscriptionManager;
	private HttpServletRequest request;

	private final String name = "mission-1";
	private final String gv = "groupvector";

	@Before
	public void setUp() {
		harness = MissionApiTestHarness.create();
		api = harness.api;
		missionService = harness.mockField("missionService");
		missionRepository = harness.mockField("missionRepository");
		subscriptionManager = harness.mockField("subscriptionManager");
		CommonUtil martiUtil = harness.mockField("martiUtil");
		request = org.mockito.Mockito.mock(HttpServletRequest.class);

		when(missionService.trimName(name)).thenReturn(name);
		when(martiUtil.getGroupVectorBitString(request)).thenReturn(gv);
	}

	@After
	public void tearDown() {
		MissionApiTestHarness.tearDown();
	}

	@Test
	public void setPassword_whenUpdateMatchesNoRow_throwsAndDoesNotBroadcast() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		when(missionService.getMission(name, gv)).thenReturn(mission);
		// group-scoped UPDATE matched nothing (mission gone / out of groups)
		when(missionRepository.setPasswordHash(eq(name), anyString(), eq(gv))).thenReturn(null);

		try {
			api.setPassword(name, "secret", "creator", request);
			fail("expected NotFoundException when the password UPDATE matched no row");
		} catch (NotFoundException expected) {
			// pass
		}

		verify(missionService, never()).invalidateMissionCache(name);
		verify(subscriptionManager, never())
				.broadcastMissionAnnouncement(any(), any(), any(), any(), any(), any());
	}

	@Test
	public void setPassword_whenUpdateApplies_invalidatesCacheAndBroadcasts() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		when(mission.getGuid()).thenReturn("11111111-1111-1111-1111-111111111111");
		when(mission.getGroupVector()).thenReturn(gv);
		when(mission.getTool()).thenReturn("public");
		when(missionService.getMission(name, gv)).thenReturn(mission);
		when(missionRepository.setPasswordHash(eq(name), anyString(), eq(gv))).thenReturn(42L);

		api.setPassword(name, "secret", "creator", request);

		verify(missionService).invalidateMissionCache(name);
		verify(subscriptionManager)
				.broadcastMissionAnnouncement(any(), any(), any(), any(), any(), any());
	}
}
