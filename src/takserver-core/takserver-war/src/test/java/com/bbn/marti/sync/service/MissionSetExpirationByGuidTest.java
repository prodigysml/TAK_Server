package com.bbn.marti.sync.service;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.UUID;

import javax.sql.DataSource;

import org.junit.After;
import org.junit.Test;

/**
 * {@link MissionServiceDefaultImpl#setExpiration(UUID, Long, String)} bound the
 * GUID as {@code missionGuid} while its SQL referenced {@code :missionName}, so
 * NamedParameterJdbcTemplate threw "No value supplied for the SQL parameter
 * 'missionName'" on every call. The GUID expiration endpoint swallows that and
 * still answers 200, so expiry-by-GUID never took effect.
 */
public class MissionSetExpirationByGuidTest {

	@After
	public void tearDown() {
		MissionServiceTestHarness.tearDown();
	}

	@Test
	public void setExpirationByGuid_bindsGuidAndUpdates() throws Exception {
		MissionServiceTestHarness harness = MissionServiceTestHarness.create();
		DataSource ds = harness.mockOf(DataSource.class);
		Connection con = mock(Connection.class);
		PreparedStatement ps = mock(PreparedStatement.class);
		when(ds.getConnection()).thenReturn(con);
		when(con.prepareStatement(anyString())).thenReturn(ps);
		when(ps.executeUpdate()).thenReturn(1);

		UUID guid = UUID.randomUUID();
		assertTrue(harness.service.setExpiration(guid, 1234L, "1"));

		verify(con).prepareStatement("update mission set expiration = ? where guid = uuid(?)");
		verify(ps).setString(2, guid.toString());
	}
}
