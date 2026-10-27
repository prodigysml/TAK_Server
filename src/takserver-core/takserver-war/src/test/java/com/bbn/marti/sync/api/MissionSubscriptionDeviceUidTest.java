package com.bbn.marti.sync.api;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.remote.exception.ForbiddenException;
import com.bbn.marti.remote.groups.User;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;

import tak.server.ignite.grid.SubscriptionManagerProxyHandler;

/**
 * Tests that a device can join or leave a mission with its own device UID.
 *
 * <p>ATAK, iTAK and WinTAK send their device UID (e.g. ANDROID-...) as 'uid', not
 * the username. Only the username used to be accepted from anyone but the
 * mission owner, so every other user was refused. A uid is now also accepted
 * when its live connection is authenticated as the caller; a device connected
 * as someone else, or not connected at all, is still refused.
 */
public class MissionSubscriptionDeviceUidTest {

	private static final String DEVICE = "ANDROID-0123456789abcdef";

	private MissionApiTestHarness harness;
	private MissionApi api;
	private MissionService missionService;
	private SubscriptionManagerLite subscriptionManagerLite;

	private final String name = "mission-1";
	private final String gv = "groupvector";

	@Before
	public void setUp() throws Exception {
		harness = MissionApiTestHarness.create();
		api = harness.api;
		missionService = harness.mockField("missionService");
		CommonUtil martiUtil = harness.mockField("martiUtil");
		HttpServletRequest request = harness.inject("request", HttpServletRequest.class);
		SubscriptionManagerProxyHandler proxy = harness.inject("subscriptionManagerProxy", SubscriptionManagerProxyHandler.class);
		subscriptionManagerLite = org.mockito.Mockito.mock(SubscriptionManagerLite.class);
		when(proxy.getSubscriptionManagerForClientUid(anyString())).thenReturn(subscriptionManagerLite);

		when(martiUtil.getGroupVectorBitString(request)).thenReturn(gv);
		when(missionService.trimName(name)).thenReturn(name);
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		when(mission.getGuidAsUUID()).thenReturn(UUID.fromString("11111111-1111-1111-1111-111111111111"));
		when(missionService.getMissionByNameCheckGroups(name, gv)).thenReturn(mission);
		// the caller is not the mission owner
		when(missionService.getRoleForRequest(any(), any())).thenReturn(null);

		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", null));
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
		MissionApiTestHarness.tearDown();
	}

	private void deviceConnectedAs(String username) {
		User user = org.mockito.Mockito.mock(User.class);
		when(user.getName()).thenReturn(username);
		when(subscriptionManagerLite.getSubscriptionUserByClientUid(DEVICE)).thenReturn(user);
	}

	@Test
	public void unsubscribe_ownDevice_isAllowed() throws Exception {
		deviceConnectedAs("alice");

		api.deleteMissionSubscription(DEVICE, "", true, name).call();

		verify(missionService).missionUnsubscribe(any(), eq(DEVICE), eq("alice"), eq(gv), anyBoolean());
	}

	@Test
	public void unsubscribe_someoneElsesDevice_isForbidden() throws Exception {
		deviceConnectedAs("bob");

		try {
			api.deleteMissionSubscription(DEVICE, "", true, name).call();
			fail("expected ForbiddenException for another user's device");
		} catch (ForbiddenException expected) {
			// pass
		}

		verify(missionService, never()).missionUnsubscribe(any(), anyString(), anyString(), anyString(), anyBoolean());
	}

	@Test
	public void unsubscribe_deviceNotConnected_isForbidden() throws Exception {
		// no live subscription for DEVICE

		try {
			api.deleteMissionSubscription(DEVICE, "", true, name).call();
			fail("expected ForbiddenException for a device that is not connected");
		} catch (ForbiddenException expected) {
			// pass
		}

		verify(missionService, never()).missionUnsubscribe(any(), anyString(), anyString(), anyString(), anyBoolean());
	}

	@Test
	public void unsubscribe_whenLookupFails_isForbidden() throws Exception {
		when(subscriptionManagerLite.getSubscriptionUserByClientUid(DEVICE)).thenThrow(new RuntimeException("not found"));

		try {
			api.deleteMissionSubscription(DEVICE, "", true, name).call();
			fail("expected ForbiddenException when the device lookup fails");
		} catch (ForbiddenException expected) {
			// pass
		}
	}
}
