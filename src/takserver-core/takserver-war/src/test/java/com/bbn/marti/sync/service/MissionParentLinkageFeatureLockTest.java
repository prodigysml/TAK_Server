package com.bbn.marti.sync.service;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.repository.MissionRepository;

/**
 * FEATURE-LOCK tests for mission parent/child re-linkage
 * ({@link MissionServiceDefaultImpl#setParent} / {@code clearParent}).
 *
 * <p>These pin the <em>current legitimate</em> behavior so the upcoming
 * "check affected rows after conditional UPDATE" fix (ZeroPath cluster #5,
 * issues f2e065c7 / 4ddbf644, CWE-252/CWE-863) does not silently change what
 * honest callers observe:
 * <ul>
 *   <li>setParent only writes + invalidates caches when the parent actually
 *       changes (it is a no-op when the parent is already correct);</li>
 *   <li>clearParent always issues the clear and invalidates the child cache,
 *       and additionally invalidates the old parent's cache when one existed.</li>
 * </ul>
 *
 * <p>These are NOT the security tests. The repository methods already return the
 * affected-row count ({@code Long}); the service currently ignores it. The
 * security test asserting the zero-rows path will be added WITH the fix so it
 * goes red-&gt;green; pinning it now would cement the bug.
 */
public class MissionParentLinkageFeatureLockTest {

	private MissionServiceTestHarness harness;
	private MissionServiceDefaultImpl service;
	private MissionRepository missionRepository;

	private final UUID child = UUID.fromString("11111111-1111-1111-1111-111111111111");
	private final UUID parent = UUID.fromString("22222222-2222-2222-2222-222222222222");
	private final String gv = "groupvector";

	@Before
	public void setUp() {
		harness = MissionServiceTestHarness.create();
		service = harness.service;
		missionRepository = harness.mockOf(MissionRepository.class);
	}

	@After
	public void tearDown() {
		MissionServiceTestHarness.tearDown();
	}

	// ---- setParent ---------------------------------------------------------

	@Test
	public void setParent_whenParentChanges_writesAndInvalidatesBothCaches() {
		when(missionRepository.getParentMissionGuid(child.toString())).thenReturn(null);

		service.setParent(child, parent, gv);

		verify(missionRepository).setParent(child.toString(), parent.toString(), gv);
		verify(harness.self).invalidateMissionCache(child);
		verify(harness.self).invalidateMissionCache(parent);
	}

	@Test
	public void setParent_whenAlreadyParentedToTarget_isNoOp() {
		// The dedupe guard now compares currentParentGuid (String) to the parent UUID
		// rendered as a String, so an unchanged parent short-circuits: no UPDATE, no
		// cache churn. (Before the String-vs-UUID fix this guard never fired.)
		when(missionRepository.getParentMissionGuid(child.toString())).thenReturn(parent.toString());

		service.setParent(child, parent, gv);

		verify(missionRepository, never()).setParent(anyString(), anyString(), anyString());
		verify(harness.self, never()).invalidateMissionCache(child);
		verify(harness.self, never()).invalidateMissionCache(parent);
	}

	@Test
	public void setParent_whenReparentingToDifferentParent_writesAndInvalidatesBothCaches() {
		UUID otherParent = UUID.fromString("33333333-3333-3333-3333-333333333333");
		when(missionRepository.getParentMissionGuid(child.toString())).thenReturn(otherParent.toString());

		service.setParent(child, parent, gv);

		verify(missionRepository).setParent(child.toString(), parent.toString(), gv);
		verify(harness.self).invalidateMissionCache(child);
		verify(harness.self).invalidateMissionCache(parent);
	}

	// ---- clearParent -------------------------------------------------------

	@Test
	public void clearParent_whenChildHasParent_invalidatesOldParentThenChild() {
		Mission childMission = org.mockito.Mockito.mock(Mission.class);
		Mission parentMission = org.mockito.Mockito.mock(Mission.class);
		when(childMission.getParent()).thenReturn(parentMission);
		when(harness.self.getMissionByGuid(child, gv)).thenReturn(childMission);
		when(missionRepository.getParentGuid(child.toString())).thenReturn(parent.toString());

		service.clearParent(child, gv);

		verify(harness.self).invalidateMissionCache(parent);
		verify(missionRepository).clearParentByGuid(child.toString(), gv);
		verify(harness.self).invalidateMissionCache(child);
	}

	@Test
	public void clearParent_whenNoExistingParent_stillClearsAndInvalidatesChildOnly() {
		Mission childMission = org.mockito.Mockito.mock(Mission.class);
		when(childMission.getParent()).thenReturn(null);
		when(harness.self.getMissionByGuid(child, gv)).thenReturn(childMission);

		service.clearParent(child, gv);

		verify(missionRepository).clearParentByGuid(child.toString(), gv);
		verify(harness.self).invalidateMissionCache(child);
		// No prior parent -> the old-parent cache invalidation path must not run.
		verify(harness.self, never()).invalidateMissionCache(parent);
		verify(missionRepository, never()).getParentGuid(anyString());
	}
}
