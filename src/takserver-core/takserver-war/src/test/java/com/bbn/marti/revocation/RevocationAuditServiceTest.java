package com.bbn.marti.revocation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.sql.DataSource;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.AssumptionViolatedException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * RevocationAuditService tests against a real PostgreSQL (via Testcontainers).
 *
 * <p>The service uses JSONB casts, {@code = ANY(?)} array predicates and
 * {@code RETURNING}-style generated keys, none of which H2 emulates faithfully,
 * so this must run against actual PostgreSQL — same reasoning as MfaServiceTest,
 * and the same deterministic self-skip when Docker is unavailable.
 *
 * <p>What is worth testing here is not the happy path but the ordering guarantee:
 * this class deletes production rows, and its whole reason to exist is that the
 * audit snapshot is written BEFORE the delete. A regression that reversed that
 * order would still pass a naive "rows are gone" assertion while destroying the
 * evidence, so the tests assert on snapshot content, not just on deletion.
 */
public class RevocationAuditServiceTest {

	private static PostgreSQLContainer<?> postgres;

	private DataSource dataSource;
	private RevocationAuditService service;

	private static final String UID = "37D1E0BA-DEAD-BEEF-0000-000000000001";
	private static final String OTHER_UID = "AAAAAAAA-0000-0000-0000-000000000002";

	@BeforeClass
	public static void startDatabase() {
		try {
			Assume.assumeTrue(
					"Docker is not available; skipping PostgreSQL-backed RevocationAuditServiceTest.",
					DockerClientFactory.instance().isDockerAvailable());
			PostgreSQLContainer<?> container = new PostgreSQLContainer<>("postgres:16-alpine");
			container.start();
			postgres = container;
		} catch (AssumptionViolatedException skip) {
			throw skip;
		} catch (Throwable t) {
			Assume.assumeNoException(
					"PostgreSQL test container could not start; skipping RevocationAuditServiceTest.", t);
		}
	}

	@AfterClass
	public static void stopDatabase() {
		if (postgres != null) {
			postgres.stop();
			postgres = null;
		}
	}

	@Before
	public void setUp() throws Exception {
		dataSource = new JdbcUrlDataSource(
				postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
		try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
			st.execute("DROP TABLE IF EXISTS client_endpoint_event");
			st.execute("DROP TABLE IF EXISTS mission_subscription");
			st.execute("DROP TABLE IF EXISTS client_endpoint");
			st.execute("DROP TABLE IF EXISTS certificate_revocation_audit");

			st.execute("CREATE TABLE client_endpoint ("
					+ "id BIGSERIAL PRIMARY KEY, callsign VARCHAR(255), uid VARCHAR(255), username VARCHAR(255))");
			st.execute("CREATE TABLE client_endpoint_event ("
					+ "id BIGSERIAL PRIMARY KEY, client_endpoint_id BIGINT)");
			st.execute("CREATE TABLE mission_subscription ("
					+ "mission_id BIGINT, client_uid VARCHAR(255), create_time TIMESTAMP,"
					+ " uid VARCHAR(255), token TEXT, role_id BIGINT, username VARCHAR(255))");
			// mirrors V95
			st.execute("CREATE TABLE certificate_revocation_audit ("
					+ "id BIGSERIAL PRIMARY KEY,"
					+ "revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,"
					+ "username VARCHAR(255), client_uid VARCHAR(255), cert_subject_dn TEXT,"
					+ "cert_serial VARCHAR(64), cert_hash VARCHAR(255),"
					+ "revoked_by VARCHAR(255) NOT NULL, revoked_via VARCHAR(32) NOT NULL,"
					+ "succeeded BOOLEAN NOT NULL DEFAULT FALSE,"
					+ "purged_rows JSONB NOT NULL DEFAULT '{}'::jsonb, notes TEXT)");

			// Target user: one row carrying the username, one anonymous row sharing the
			// device uid — the shape an input without auth="x509" actually produces.
			st.execute("INSERT INTO client_endpoint (callsign, uid, username) VALUES "
					+ "('CPO-Z', '" + UID + "', 'Zak'), ('CPO-Z', '" + UID + "', '')");
			st.execute("INSERT INTO client_endpoint_event (client_endpoint_id) "
					+ "SELECT id FROM client_endpoint WHERE uid = '" + UID + "'");
			st.execute("INSERT INTO mission_subscription "
					+ "(mission_id, client_uid, create_time, uid, token, role_id, username) VALUES "
					+ "(7, '" + UID + "', CURRENT_TIMESTAMP, 'sub-1', 'eyJhbGciOiJIUzI1NiJ9.secret', 1, 'Zak')");

			// Bystander that must survive untouched.
			st.execute("INSERT INTO client_endpoint (callsign, uid, username) VALUES ('Keeper', '" + OTHER_UID + "', 'hugh')");
			st.execute("INSERT INTO mission_subscription "
					+ "(mission_id, client_uid, create_time, uid, token, role_id, username) VALUES "
					+ "(7, '" + OTHER_UID + "', CURRENT_TIMESTAMP, 'sub-2', 'other-token', 1, 'hugh')");
		}
		service = new RevocationAuditService(new SingleValueObjectProvider<>(dataSource));
	}

	@After
	public void tearDown() throws Exception {
		if (dataSource == null) {
			return;
		}
		try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
			st.execute("DROP TABLE IF EXISTS client_endpoint_event");
			st.execute("DROP TABLE IF EXISTS mission_subscription");
			st.execute("DROP TABLE IF EXISTS client_endpoint");
			st.execute("DROP TABLE IF EXISTS certificate_revocation_audit");
		}
	}

	@Test
	public void purgesEveryRowForTheUserIncludingAnonymousDuplicates() throws Exception {
		long id = service.purgeAndAudit("Zak", UID, "CN=Zak", "DEADBEEF", "hash1",
				"admin@example.com", RevocationAuditService.Source.ADMIN_UI);
		assertTrue("audit row should have been created", id > 0);

		assertEquals(0, count("SELECT count(*) FROM client_endpoint WHERE uid = '" + UID + "'"));
		assertEquals(0, count("SELECT count(*) FROM mission_subscription WHERE client_uid = '" + UID + "'"));
		assertEquals(0, count("SELECT count(*) FROM client_endpoint_event"));
	}

	@Test
	public void leavesOtherUsersAlone() throws Exception {
		service.purgeAndAudit("Zak", UID, "CN=Zak", "DEADBEEF", "hash1",
				"admin@example.com", RevocationAuditService.Source.ADMIN_UI);

		assertEquals(1, count("SELECT count(*) FROM client_endpoint WHERE uid = '" + OTHER_UID + "'"));
		assertEquals(1, count("SELECT count(*) FROM mission_subscription WHERE client_uid = '" + OTHER_UID + "'"));
	}

	@Test
	public void snapshotCapturesRowsBeforeTheyAreDeleted() throws Exception {
		long id = service.purgeAndAudit("Zak", UID, "CN=Zak", "DEADBEEF", "hash1",
				"admin@example.com", RevocationAuditService.Source.ADMIN_UI);

		String snapshot = queryString(
				"SELECT purged_rows::text FROM certificate_revocation_audit WHERE id = " + id);
		assertNotNull(snapshot);
		// The rows are gone from their tables, so this content can only have come
		// from a snapshot taken before the delete.
		assertTrue("snapshot should record the callsign", snapshot.contains("CPO-Z"));
		assertTrue("snapshot should record the mission subscription", snapshot.contains("sub-1"));
		assertTrue("snapshot should record the event count",
				snapshot.contains("\"client_endpoint_event_count\": 2")
						|| snapshot.contains("\"client_endpoint_event_count\":2"));
	}

	@Test
	public void redactsBearerTokenFromTheSnapshot() throws Exception {
		long id = service.purgeAndAudit("Zak", UID, "CN=Zak", "DEADBEEF", "hash1",
				"admin@example.com", RevocationAuditService.Source.ADMIN_UI);

		String snapshot = queryString(
				"SELECT purged_rows::text FROM certificate_revocation_audit WHERE id = " + id);
		assertFalse("the raw subscription JWT must not survive into the audit table",
				snapshot.contains("eyJhbGciOiJIUzI1NiJ9.secret"));
		assertTrue("a correlatable digest should replace it", snapshot.contains("sha256:"));
	}

	@Test
	public void recordsWhoRevokedAndThroughWhichPath() throws Exception {
		long id = service.purgeAndAudit("Zak", UID, "CN=Zak", "DEADBEEF", "hash1",
				"admin@example.com", RevocationAuditService.Source.ADMIN_UI);

		assertEquals("admin@example.com",
				queryString("SELECT revoked_by FROM certificate_revocation_audit WHERE id = " + id));
		assertEquals("admin-ui",
				queryString("SELECT revoked_via FROM certificate_revocation_audit WHERE id = " + id));
		assertEquals("t",
				queryString("SELECT succeeded::text FROM certificate_revocation_audit WHERE id = " + id));
	}

	/**
	 * Regression: a user with a mission_subscription but no client_endpoint row.
	 * Resolving device UIDs from client_endpoint alone finds nothing for them, so
	 * the subscription and its bearer token survive a revocation silently. Seen in
	 * production on a user who was invited to a mission but never connected.
	 */
	@Test
	public void purgesSubscriptionForUserWithNoClientEndpointRow() throws Exception {
		final String lonelyUid = "BBBBBBBB-0000-0000-0000-000000000003";
		try (Connection c = dataSource.getConnection(); Statement st = c.createStatement()) {
			st.execute("INSERT INTO mission_subscription "
					+ "(mission_id, client_uid, create_time, uid, token, role_id, username) VALUES "
					+ "(6, '" + lonelyUid + "', CURRENT_TIMESTAMP, 'sub-3', 'lonely-token', 1, 'SH')");
		}

		long id = service.purgeAndAudit("SH", null, "CN=SH", "CAFE", "hash2",
				"admin@example.com", RevocationAuditService.Source.ADMIN_UI);

		assertTrue("audit row should have been created", id > 0);
		assertEquals("subscription must be purged even with no client_endpoint row",
				0, count("SELECT count(*) FROM mission_subscription WHERE client_uid = '" + lonelyUid + "'"));

		String snapshot = queryString(
				"SELECT purged_rows::text FROM certificate_revocation_audit WHERE id = " + id);
		assertTrue("snapshot should record the subscription", snapshot.contains("sub-3"));
		assertFalse("the raw token must not survive into the audit table",
				snapshot.contains("lonely-token"));
	}

	@Test
	public void auditsEvenWhenThereIsNothingToPurge() throws Exception {
		long id = service.purgeAndAudit("NoSuchUser", null, "CN=NoSuchUser", "0000", "hash9",
				"admin@example.com", RevocationAuditService.Source.OPERATOR_CLI);

		assertTrue("a revocation with no operational rows is still worth recording", id > 0);
		assertEquals("operator-cli",
				queryString("SELECT revoked_via FROM certificate_revocation_audit WHERE id = " + id));
	}

	private int count(String sql) throws Exception {
		return Integer.parseInt(queryString(sql));
	}

	private String queryString(String sql) throws Exception {
		try (Connection c = dataSource.getConnection();
				Statement st = c.createStatement();
				ResultSet rs = st.executeQuery(sql)) {
			return rs.next() ? rs.getString(1) : null;
		}
	}

	private static final class JdbcUrlDataSource implements DataSource {
		private final String url;
		private final String user;
		private final String password;
		JdbcUrlDataSource(String url, String user, String password) {
			this.url = url;
			this.user = user;
			this.password = password;
		}
		@Override public Connection getConnection() throws java.sql.SQLException {
			return DriverManager.getConnection(url, user, password);
		}
		@Override public Connection getConnection(String u, String p) throws java.sql.SQLException {
			return DriverManager.getConnection(url, u, p);
		}
		@Override public java.io.PrintWriter getLogWriter() { return null; }
		@Override public void setLogWriter(java.io.PrintWriter out) {}
		@Override public void setLoginTimeout(int seconds) {}
		@Override public int getLoginTimeout() { return 0; }
		@Override public java.util.logging.Logger getParentLogger() { return null; }
		@Override public <T> T unwrap(Class<T> iface) { return null; }
		@Override public boolean isWrapperFor(Class<?> iface) { return false; }
	}

	/** Tiny ObjectProvider stub that returns a single pre-bound value. */
	private static final class SingleValueObjectProvider<T> implements ObjectProvider<T> {
		private final T value;
		SingleValueObjectProvider(T value) { this.value = value; }
		@Override public T getObject() { return value; }
		@Override public T getObject(Object... args) { return value; }
		@Override public T getIfAvailable() { return value; }
		@Override public T getIfUnique() { return value; }
	}
}
