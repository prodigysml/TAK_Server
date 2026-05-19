package com.bbn.marti.mfa;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.Optional;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Per-user TOTP secret persistence. One row per username keyed by exact
 * UserAuthenticationFile.xml identifier. Mutations all go through this
 * class so the audit story is in one place; callers should not poke the
 * table directly.
 *
 * The CLI reset path bypasses this service intentionally — operators run
 * straight SQL via the Taskfile so a compromised admin session cannot
 * trigger a reset by reaching this code.
 *
 * The DataSource is supplied via an ObjectProvider, so the HikariCP pool
 * is materialized lazily on the first MFA call instead of at bean
 * creation time. An earlier eager-injection version blocked Spring
 * bootstrap long enough that the servlet container never opened 8443 and
 * ECS health-checks SIGKILLed the container.
 */
public class MfaService {

	private static final Logger logger = LoggerFactory.getLogger(MfaService.class);

	private final ObjectProvider<DataSource> dataSourceProvider;

	public MfaService(ObjectProvider<DataSource> dataSourceProvider) {
		this.dataSourceProvider = dataSourceProvider;
	}

	private DataSource ds() {
		DataSource ds = dataSourceProvider.getIfAvailable();
		if (ds == null) {
			throw new IllegalStateException("DataSource not yet available");
		}
		return ds;
	}

	public Optional<MfaRow> findByUsername(String username) {
		String sql = "SELECT username, secret_b32, enrolled, enrolled_at, last_used_at "
				+ "FROM user_totp_secret WHERE username = ?";
		try (var c = ds().getConnection();
				PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, username);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) return Optional.empty();
				MfaRow r = new MfaRow();
				r.username = rs.getString("username");
				r.secretB32 = rs.getString("secret_b32");
				r.enrolled = rs.getBoolean("enrolled");
				r.enrolledAt = rs.getTimestamp("enrolled_at");
				r.lastUsedAt = rs.getTimestamp("last_used_at");
				return Optional.of(r);
			}
		} catch (Exception e) {
			logger.error("findByUsername failed for {}", username, e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Provision an un-enrolled row with a fresh secret. Used on first login
	 * when no row exists yet. If a row already exists (e.g. user revisited
	 * the enroll page before confirming), return the existing un-enrolled
	 * row unchanged so they can complete the same secret in their app.
	 * Returning the existing secret on revisit is safe — the row stays
	 * enrolled=false until the user submits a valid code.
	 */
	public MfaRow getOrProvision(String username) {
		Optional<MfaRow> existing = findByUsername(username);
		if (existing.isPresent()) return existing.get();
		String secret = TotpUtil.generateSecret();
		String sql = "INSERT INTO user_totp_secret(username, secret_b32, enrolled) VALUES(?, ?, FALSE) "
				+ "ON CONFLICT (username) DO NOTHING";
		try (var c = ds().getConnection();
				PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, username);
			ps.setString(2, secret);
			ps.executeUpdate();
		} catch (Exception e) {
			logger.error("provision failed for {}", username, e);
			throw new RuntimeException(e);
		}
		return findByUsername(username).orElseThrow();
	}

	public void markEnrolled(String username) {
		String sql = "UPDATE user_totp_secret SET enrolled = TRUE, enrolled_at = CURRENT_TIMESTAMP, "
				+ "last_used_at = CURRENT_TIMESTAMP WHERE username = ? AND enrolled = FALSE";
		try (var c = ds().getConnection();
				PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, username);
			ps.executeUpdate();
		} catch (Exception e) {
			logger.error("markEnrolled failed for {}", username, e);
			throw new RuntimeException(e);
		}
	}

	public void touchLastUsed(String username) {
		String sql = "UPDATE user_totp_secret SET last_used_at = CURRENT_TIMESTAMP WHERE username = ?";
		try (var c = ds().getConnection();
				PreparedStatement ps = c.prepareStatement(sql)) {
			ps.setString(1, username);
			ps.executeUpdate();
		} catch (Exception e) {
			// Best-effort timestamp update; do not fail the verify call if this misses.
			logger.warn("touchLastUsed failed for {}", username, e);
		}
	}

	public static class MfaRow {
		public String username;
		public String secretB32;
		public boolean enrolled;
		public Timestamp enrolledAt;
		public Timestamp lastUsedAt;
	}
}
