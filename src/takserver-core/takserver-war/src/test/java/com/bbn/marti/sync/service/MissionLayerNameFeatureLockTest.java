package com.bbn.marti.sync.service;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.remote.exception.NotFoundException;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.model.MissionLayer;
import com.bbn.marti.sync.repository.MissionLayerRepository;

/**
 * Tests for {@link MissionServiceDefaultImpl#setLayerName} (ZeroPath cluster #5,
 * issue a2034574, CWE-362/697).
 *
 * <p>setLayerName validates that the layer exists and belongs to the mission,
 * then runs a conditional UPDATE and announces a mission-layer change. The
 * UPDATE row count was discarded, so a layer deleted between the validation and
 * the update (TOCTOU) would still broadcast a rename for a layer that no longer
 * exists. setName now returns the row count and setLayerName throws
 * NotFoundException (and announces nothing) when it is zero.
 */
public class MissionLayerNameFeatureLockTest {

	private MissionServiceTestHarness harness;
	private MissionServiceDefaultImpl service;
	private MissionLayerRepository layerRepository;
	private SubscriptionManagerLite subscriptionManager;

	private final String layerUid = "layer-1";
	private final Long missionId = 1L;

	@Before
	public void setUp() {
		harness = MissionServiceTestHarness.create();
		service = harness.service;
		layerRepository = harness.mockOf(MissionLayerRepository.class);
		subscriptionManager = harness.mockOf(SubscriptionManagerLite.class);
	}

	@After
	public void tearDown() {
		MissionServiceTestHarness.tearDown();
	}

	private Mission validatedMission() {
		Mission mission = org.mockito.Mockito.mock(Mission.class);
		when(mission.getId()).thenReturn(missionId);
		// layer exists and belongs to the mission (passes the pre-checks)
		when(layerRepository.findByUidNoMission(layerUid)).thenReturn(new MissionLayer(layerUid));
		when(layerRepository.countByUidAndMissionId(layerUid, missionId)).thenReturn(1);
		return mission;
	}

	@Test
	public void setLayerName_whenUpdateMatchesNoRow_throwsAndAnnouncesNothing() {
		Mission mission = validatedMission();
		when(layerRepository.setName(layerUid, "new-name")).thenReturn(0);

		try {
			service.setLayerName("mission-1", mission, layerUid, "new-name", "creator");
			fail("expected NotFoundException when the layer rename matched no row");
		} catch (NotFoundException expected) {
			// pass
		}

		verify(subscriptionManager, never())
				.announceMissionChange(any(), any(), any(), any(), any(), any());
	}

	@Test
	public void setLayerName_whenUpdateApplies_announcesChange() {
		Mission mission = validatedMission();
		when(mission.getGuidAsUUID()).thenReturn(UUID.fromString("11111111-1111-1111-1111-111111111111"));
		when(mission.getName()).thenReturn("mission-1");
		when(mission.getTool()).thenReturn("public");
		when(layerRepository.setName(layerUid, "new-name")).thenReturn(1);

		service.setLayerName("mission-1", mission, layerUid, "new-name", "creator");

		verify(subscriptionManager)
				.announceMissionChange(any(), any(), any(), any(), any(), any());
	}
}
