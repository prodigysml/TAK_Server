package com.bbn.marti.sync.service;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import com.bbn.marti.remote.RemoteSubscription;
import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.sync.model.MissionInvitation;
import com.bbn.marti.sync.repository.MissionInvitationRepository;

import tak.server.ignite.grid.SubscriptionManagerProxyHandler;

/**
 * {@link MissionServiceDefaultImpl#getAllMissionInvitationsForClient} must only
 * return clientUid/callsign invitations when the subscription is proven to belong
 * to the caller. A subscription with neither a user nor a username used to skip
 * the ownership check entirely and return another client's invitations.
 */
public class MissionInvitationOwnershipTest {

	private static final String GV = "1";

	private MissionServiceTestHarness harness;
	private MissionInvitationRepository repo;
	private SubscriptionManagerLite subMgr;

	@Before
	public void setUp() {
		harness = MissionServiceTestHarness.create();
		repo = harness.mockOf(MissionInvitationRepository.class);
		SubscriptionManagerProxyHandler proxy = harness.mockOf(SubscriptionManagerProxyHandler.class);
		subMgr = mock(SubscriptionManagerLite.class);
		when(proxy.getSubscriptionManagerForClientUid(anyString())).thenReturn(subMgr);
		when(repo.findAllMissionInvitationsByInviteeIgnoreCaseAndType(anyString(), anyString(), anyString()))
				.thenReturn(Collections.emptyList());
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("alice", "n/a", Collections.emptyList()));
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
		MissionServiceTestHarness.tearDown();
	}

	@Test
	public void ownerlessSubscription_doesNotReturnClientUidOrCallsignInvitations() {
		RemoteSubscription sub = new RemoteSubscription();
		sub.callsign = "BOB";
		when(subMgr.getRemoteSubscriptionByClientUid("bob-uid")).thenReturn(sub);

		Set<MissionInvitation> result = harness.service.getAllMissionInvitationsForClient("bob-uid", GV);

		assertTrue(result.isEmpty());
		verify(repo, never()).findAllMissionInvitationsByInviteeIgnoreCaseAndType(
				eq("bob-uid"), eq(MissionInvitation.Type.clientUid.name()), anyString());
		verify(repo, never()).findAllMissionInvitationsByInviteeIgnoreCaseAndType(
				eq("BOB"), eq(MissionInvitation.Type.callsign.name()), anyString());
		verify(repo).findAllMissionInvitationsByInviteeIgnoreCaseAndType(
				"alice", MissionInvitation.Type.userName.name(), GV);
	}

	@Test
	public void ownedSubscription_returnsClientUidAndCallsignInvitations() {
		RemoteSubscription sub = new RemoteSubscription();
		sub.callsign = "ALICE";
		sub.setUsername("alice");
		when(subMgr.getRemoteSubscriptionByClientUid("alice-uid")).thenReturn(sub);

		harness.service.getAllMissionInvitationsForClient("alice-uid", GV);

		verify(repo).findAllMissionInvitationsByInviteeIgnoreCaseAndType(
				"alice-uid", MissionInvitation.Type.clientUid.name(), GV);
		verify(repo).findAllMissionInvitationsByInviteeIgnoreCaseAndType(
				"ALICE", MissionInvitation.Type.callsign.name(), GV);
	}
}
