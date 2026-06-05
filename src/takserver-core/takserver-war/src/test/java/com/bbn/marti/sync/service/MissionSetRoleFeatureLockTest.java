package com.bbn.marti.sync.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.model.MissionRole;

/**
 * Tests for {@link MissionServiceDefaultImpl#setRole} (ZeroPath cluster #5,
 * issue 0c44819e, CWE-252/703/841).
 *
 * <p>The role assignment is a conditional UPDATE keyed on
 * (clientUid|username, missionId). It previously discarded the affected-row
 * count, so a no-match update returned success and still broadcast a
 * mission-role change for a role that was never applied. setRole now returns
 * false and broadcasts nothing when the UPDATE matches no subscription row.
 *
 * <p>The DB call is exercised through the self-proxy seam
 * ({@code getMissionService().setRoleByClientUidOrUsername}) so the decision
 * logic is unit-tested without a live database; the JDBC row count itself is
 * covered by integration tests against PostgreSQL.
 */
public class MissionSetRoleFeatureLockTest {

	private MissionServiceTestHarness harness;
	private MissionServiceDefaultImpl service;
	private SubscriptionManagerLite subscriptionManager;

	private final Long missionId = 1L;
	private final Long roleId = 5L;
	private final String clientUid = "client-1";

	@Before
	public void setUp() {
		harness = MissionServiceTestHarness.create();
		service = harness.service;
		subscriptionManager = harness.mockOf(SubscriptionManagerLite.class);
	}

	@After
	public void tearDown() {
		MissionServiceTestHarness.tearDown();
	}

	@Test
	public void setRole_whenUpdateMatchesNoSubscription_returnsFalseAndBroadcastsNothing() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		MissionRole role = org.mockito.Mockito.mock(MissionRole.class);
		when(mission.getId()).thenReturn(missionId);
		when(role.getId()).thenReturn(roleId);
		when(harness.self.setRoleByClientUidOrUsername(missionId, clientUid, null, roleId)).thenReturn(0);

		boolean result = service.setRole(mission, clientUid, null, role, "groupvector");

		assertFalse("no matching subscription row -> role not applied -> failure", result);
		verify(subscriptionManager, never())
				.sendMissionRoleChange(any(), any(), any(), any(), any(), any());
	}

	@Test
	public void setRole_whenUpdateAppliesToSubscription_returnsTrueAndBroadcasts() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		MissionRole role = org.mockito.Mockito.mock(MissionRole.class);
		when(mission.getId()).thenReturn(missionId);
		when(mission.getGuid()).thenReturn("11111111-1111-1111-1111-111111111111");
		when(mission.getName()).thenReturn("mission-1");
		when(mission.getTool()).thenReturn("public");
		when(role.getId()).thenReturn(roleId);
		when(harness.self.setRoleByClientUidOrUsername(missionId, clientUid, null, roleId)).thenReturn(1);

		boolean result = service.setRole(mission, clientUid, null, role, "groupvector");

		assertTrue("matching subscription row -> role applied -> success", result);
		verify(subscriptionManager)
				.sendMissionRoleChange(any(), any(), any(), any(), any(), any());
	}
}
