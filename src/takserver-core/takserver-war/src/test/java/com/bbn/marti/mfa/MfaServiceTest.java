package com.bbn.marti.mfa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Optional;

import javax.sql.DataSource;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.ObjectProvider;

/**
 * MfaService tests against an in-memory H2 database with the V94 schema
 * mirrored as a CREATE TABLE. Exercises provision -> enroll -> verify
 * round-trip as well as idempotency on re-provision.
 *
 * The ObjectProvider used by MfaService is faked here with an inline
 * implementation that returns the H2 DataSource on demand; mirrors how
 * Spring's lazy lookup behaves in production without dragging in the
 * full ApplicationContext.
 */
public class MfaServiceTest {

	private static final String JDBC_URL = "jdbc:h2:mem:mfaservicetest;DB_CLOSE_DELAY=-1;MODE=PostgreSQL";

	private DataSource dataSource;
	private MfaService service;

	@Before
	public void setUp() throws Exception {
		dataSource = new SimpleH2DataSource(JDBC_URL);
		try (Connection c = dataSource.getConnection();
				Statement st = c.createStatement()) {
			st.execute("DROP TABLE IF EXISTS user_totp_secret");
			st.execute("CREATE TABLE user_totp_secret ("
					+ "username VARCHAR(64) PRIMARY KEY,"
					+ "secret_b32 VARCHAR(64) NOT NULL,"
					+ "enrolled BOOLEAN NOT NULL DEFAULT FALSE,"
					+ "enrolled_at TIMESTAMP NULL,"
					+ "last_used_at TIMESTAMP NULL,"
					+ "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
					+ ")");
		}
		service = new MfaService(new SingleValueObjectProvider<>(dataSource));
	}

	@After
	public void tearDown() throws Exception {
		try (Connection c = dataSource.getConnection();
				Statement st = c.createStatement()) {
			st.execute("DROP TABLE IF EXISTS user_totp_secret");
		}
	}

	@Test
	public void findByUsernameReturnsEmptyForNewUser() {
		Optional<MfaService.MfaRow> r = service.findByUsername("nobody");
		assertFalse(r.isPresent());
	}

	@Test
	public void getOrProvisionCreatesUnenrolledRow() {
		MfaService.MfaRow row = service.getOrProvision("alice");
		assertEquals("alice", row.username);
		assertFalse(row.enrolled);
		// Base32 secret, 32 chars (160 bits) — same length as TotpUtil.generateSecret()
		assertEquals(32, row.secretB32.length());
		assertTrue(row.secretB32.matches("^[A-Z2-7]+$"));
	}

	@Test
	public void getOrProvisionIsIdempotent() {
		MfaService.MfaRow first = service.getOrProvision("bob");
		MfaService.MfaRow second = service.getOrProvision("bob");
		assertEquals("re-provisioning must return same secret",
				first.secretB32, second.secretB32);
		assertFalse(second.enrolled);
	}

	@Test
	public void markEnrolledFlipsFlag() {
		service.getOrProvision("carol");
		service.markEnrolled("carol");
		MfaService.MfaRow row = service.findByUsername("carol").orElseThrow();
		assertTrue(row.enrolled);
		assertTrue("enrolled_at should be set", row.enrolledAt != null);
	}

	@Test
	public void markEnrolledIsNoOpForAlreadyEnrolledUser() {
		service.getOrProvision("dan");
		service.markEnrolled("dan");
		MfaService.MfaRow first = service.findByUsername("dan").orElseThrow();
		try { Thread.sleep(5); } catch (InterruptedException ignored) {}
		service.markEnrolled("dan"); // second call should not bump enrolled_at
		MfaService.MfaRow second = service.findByUsername("dan").orElseThrow();
		assertEquals(first.enrolledAt, second.enrolledAt);
	}

	@Test
	public void touchLastUsedUpdatesTimestamp() throws InterruptedException {
		service.getOrProvision("erin");
		service.markEnrolled("erin");
		java.sql.Timestamp before = service.findByUsername("erin").orElseThrow().lastUsedAt;
		Thread.sleep(15);
		service.touchLastUsed("erin");
		java.sql.Timestamp after = service.findByUsername("erin").orElseThrow().lastUsedAt;
		assertTrue("last_used_at must advance", after.after(before));
	}

	@Test
	public void touchLastUsedSwallowsErrors() {
		// touch on unknown user should not throw — best-effort
		service.touchLastUsed("ghost");
	}

	@Test
	public void serviceFailsLoudlyWhenDataSourceUnavailable() {
		MfaService unbound = new MfaService(new SingleValueObjectProvider<>(null));
		try {
			unbound.findByUsername("anyone");
			fail("expected IllegalStateException");
		} catch (IllegalStateException expected) {
			// pass
		}
	}

	/** Minimal DataSource that hands out JDBC connections from DriverManager. */
	private static final class SimpleH2DataSource implements DataSource {
		private final String url;
		SimpleH2DataSource(String url) { this.url = url; }
		@Override public Connection getConnection() throws java.sql.SQLException {
			return DriverManager.getConnection(url, "sa", "");
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
