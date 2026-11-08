package com.bbn.marti.sync.api;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.bbn.marti.remote.exception.ForbiddenException;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.model.MissionPermission;
import com.bbn.marti.sync.model.MissionRole;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;

/**
 * PUT /missions/{child}/parent/{parent}: the @PreAuthorize MISSION_WRITE check only
 * covers the child mission, so the caller must also have write access on the parent.
 * Being in the parent's groups (read-only role, or a password/invite-only parent
 * with no token) is not enough to change its hierarchy.
 */
public class MissionSetParentAuthorizationTest {

	private static final UUID CHILD = UUID.fromString("11111111-1111-1111-1111-111111111111");
	private static final UUID PARENT = UUID.fromString("22222222-2222-2222-2222-222222222222");

	private MissionApi api;
	private MissionService missionService;
	private HttpServletRequest request;
	private Mission parent;

	@Before
	public void setUp() throws Exception {
		MissionApiTestHarness harness = MissionApiTestHarness.create();
		api = harness.api;
		missionService = harness.mockField("missionService");
		CommonUtil martiUtil = harness.mockField("martiUtil");
		request = mock(HttpServletRequest.class);

		when(martiUtil.getGroupVectorBitString(request)).thenReturn("gv");
		when(missionService.trimName(anyString())).thenAnswer(i -> i.getArgument(0));
		Mission child = mock(Mission.class);
		when(child.getGuidAsUUID()).thenReturn(CHILD);
		parent = mock(Mission.class);
		when(parent.getGuidAsUUID()).thenReturn(PARENT);
		when(parent.getName()).thenReturn("parent");
		when(missionService.getMissionByNameCheckGroups("child", "gv")).thenReturn(child);
		when(missionService.getMissionByNameCheckGroups("parent", "gv")).thenReturn(parent);
		when(missionService.getMissionByGuidCheckGroups(CHILD, "gv")).thenReturn(child);
		when(missionService.getMissionByGuidCheckGroups(PARENT, "gv")).thenReturn(parent);
	}

	@After
	public void tearDown() {
		MissionApiTestHarness.tearDown();
	}

	private void parentRole(boolean canWrite) {
		MissionRole role = mock(MissionRole.class);
		when(role.hasPermission(MissionPermission.Permission.MISSION_WRITE)).thenReturn(canWrite);
		when(missionService.getRoleForRequest(parent, request)).thenReturn(role);
	}

	@Test
	public void readOnlyOnParentIsRefused() {
		parentRole(false);
		try {
			api.setParent("child", "parent", request);
			fail("expected ForbiddenException");
		} catch (ForbiddenException expected) { }
		try {
			api.setParentByGuid(CHILD.toString(), PARENT.toString(), request);
			fail("expected ForbiddenException");
		} catch (ForbiddenException expected) { }
		verify(missionService, never()).setParent(any(), any(), any());
	}

	@Test
	public void noRoleOnParentIsRefused() {
		when(missionService.getRoleForRequest(parent, request)).thenReturn(null);
		try {
			api.setParent("child", "parent", request);
			fail("expected ForbiddenException");
		} catch (ForbiddenException expected) { }
		verify(missionService, never()).setParent(any(), any(), any());
	}

	@Test
	public void writerOnParentIsAllowed() {
		parentRole(true);
		api.setParent("child", "parent", request);
		api.setParentByGuid(CHILD.toString(), PARENT.toString(), request);
		verify(missionService, org.mockito.Mockito.times(2)).setParent(CHILD, PARENT, "gv");
	}
}
