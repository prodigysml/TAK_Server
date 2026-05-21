package com.bbn.marti.sync;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.bbn.marti.sync.service.MissionServiceDefaultImpl;

/**
 * Reasonable-defaults bounds check for the mission-layer recursion + child
 * iteration caps added to MissionServiceDefaultImpl. The full helpers are
 * private (depth-recursion) or instance methods, so this test pins the
 * public constants only. Behavior is covered by deeper integration tests
 * that drive the recursion through the public removeMissionLayer entry.
 */
public class MissionLayerDepthCapTest {

	@Test
	public void layerDepthCapIsReasonable() {
		assertTrue(MissionServiceDefaultImpl.MAX_MISSION_LAYER_DEPTH >= 8);
		assertTrue(MissionServiceDefaultImpl.MAX_MISSION_LAYER_DEPTH <= 1024);
	}

	@Test
	public void layerNodeCapIsReasonable() {
		assertTrue(MissionServiceDefaultImpl.MAX_MISSION_LAYER_NODES >= 64);
		assertTrue(MissionServiceDefaultImpl.MAX_MISSION_LAYER_NODES <= 1_000_000);
	}

	@Test
	public void childrenLookupCapIsReasonable() {
		assertTrue(MissionServiceDefaultImpl.MAX_MISSION_CHILDREN_PER_LOOKUP >= 16);
		assertTrue(MissionServiceDefaultImpl.MAX_MISSION_CHILDREN_PER_LOOKUP <= 100_000);
	}
}
