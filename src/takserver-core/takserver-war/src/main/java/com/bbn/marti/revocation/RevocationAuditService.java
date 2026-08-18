package com.bbn.marti.revocation;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Records what a certificate revocation destroyed, and then destroys it.
 *
 * <p>Revocation is inherently lossy. The serial goes to the CRL, the account
 * leaves UserAuthenticationFile.xml, and the rows that make a user visible in
 * the admin UI are purged — otherwise a revoked callsign keeps appearing in the
 * client list as though still connected, which reads to an operator as "the
 * revocation did not work". Purging those rows without recording them first
 * would delete the only evidence the user was ever on the server.
 *
 * <p>Every purge therefore writes one {@code certificate_revocation_audit} row
 * containing a JSON snapshot of the exact rows removed, captured BEFORE the
 * delete, plus who did it and through which path. The audit insert is committed
 * on its own connection first; if the purge then fails, the audit row survives
 * with {@code succeeded = false} rather than being rolled back into nothing.
 *
 * <p>Secrets are redacted on the way in. {@code mission_subscription.token} is a
 * bearer credential — copying it into an audit table that outlives the
 * subscription would keep a usable credential alive long after the user was
 * removed, so only a SHA-256 prefix is retained: enough to correlate this row
 * with an earlier log line, useless for authenticating.
 *
 * <p>The DataSource is supplied via an ObjectProvider so the connection pool is
 * materialized lazily rather than at bean-creation time, matching MfaService.
 * Eager injection there once blocked Spring bootstrap long enough that the
 * servlet container never opened its port and ECS health-checks killed the
 * container; do not "simplify" this to a constructor-injected DataSource.
 */
public class RevocationAuditService {

	private static final Logger logger = LoggerFactory.getLogger(RevocationAuditService.class);

	/** Column names whose values must never be copied into the audit snapshot. */
	private static final List<String> REDACT_COLUMNS = List.of("token", "password", "passwordhash", "secret_b32");

	private final ObjectProvider<DataSource> dataSourceProvider;

	public RevocationAuditService(ObjectProvider<DataSource> dataSourceProvider) {
		this.dataSourceProvider = dataSourceProvider;
	}

	private DataSource ds() {
		DataSource ds = dataSourceProvider.getIfAvailable();
		if (ds == null) {
			throw new IllegalStateException("DataSource not yet available");
		}
		return ds;
	}

	/** Where a revocation was initiated from. Stored verbatim in revoked_via. */
	public enum Source {
		ADMIN_UI("admin-ui"),
		OPERATOR_CLI("operator-cli");

		private final String value;

		Source(String value) {
			this.value = value;
		}

		public String getValue() {
			return value;
		}
	}

	/**
	 * Snapshot and purge every operational row belonging to a revoked user, then
	 * record what was removed.
	 *
	 * <p>Rows are matched by client UID and by username, because an input without
	 * {@code auth="x509"} auto-enrolls cert clients anonymously: the same device
	 * accumulates {@code client_endpoint} rows with the username filled in AND
	 * rows with an empty username sharing the device UID. Matching on username
	 * alone leaves the anonymous duplicates behind, and the callsign keeps
	 * reappearing in the UI.
	 *
	 * @return the audit row id, or -1 if the audit row could not be written (in
	 *         which case NOTHING is purged — an unrecorded purge is not performed)
	 */
	public long purgeAndAudit(String username, String clientUid, String certSubjectDn,
			String certSerial, String certHash, String revokedBy, Source source) {

		StringBuilder snapshot = new StringBuilder("{");
		List<String> notes = new ArrayList<>();
		long auditId = -1;

		try (Connection con = ds().getConnection()) {

			// ---- 1. snapshot, before anything is deleted -------------------
			List<String> uids = resolveUids(con, username, clientUid);

			String endpointJson = snapshotRows(con,
					"SELECT * FROM client_endpoint WHERE uid = ANY(?)", uids);
			String subscriptionJson = snapshotRows(con,
					"SELECT ms.* FROM mission_subscription ms WHERE ms.client_uid = ANY(?)", uids);
			int eventCount = countRows(con,
					"SELECT count(*) FROM client_endpoint_event WHERE client_endpoint_id IN "
							+ "(SELECT id FROM client_endpoint WHERE uid = ANY(?))", uids);

			snapshot.append("\"matched_uids\":").append(toJsonArray(uids))
					.append(",\"client_endpoint\":").append(endpointJson)
					.append(",\"mission_subscription\":").append(subscriptionJson)
					.append(",\"client_endpoint_event_count\":").append(eventCount)
					.append("}");

			// ---- 2. write the audit row FIRST, on its own transaction ------
			auditId = insertAudit(con, username, clientUid, certSubjectDn, certSerial, certHash,
					revokedBy, source, snapshot.toString(), null, false);

			if (auditId < 0) {
				logger.error("revocation audit row could not be written for {} — refusing to purge", username);
				return -1;
			}

			// ---- 3. only now, purge ---------------------------------------
			int subs = executePurge(con,
					"DELETE FROM mission_subscription WHERE client_uid = ANY(?)", uids);
			int events = executePurge(con,
					"DELETE FROM client_endpoint_event WHERE client_endpoint_id IN "
							+ "(SELECT id FROM client_endpoint WHERE uid = ANY(?))", uids);
			int endpoints = executePurge(con,
					"DELETE FROM client_endpoint WHERE uid = ANY(?)", uids);

			notes.add(String.format(Locale.ROOT,
					"purged mission_subscription=%d client_endpoint_event=%d client_endpoint=%d", subs, events, endpoints));

			// CoT history in cot_router is deliberately NOT touched. latestcot is a
			// view over it, and it is the record of what the user actually did — the
			// opposite of something to delete while building an audit trail.
			notes.add("cot_router history retained");

			markSucceeded(con, auditId, String.join("; ", notes));

		} catch (Exception e) {
			logger.error("exception during revocation purge for {}", username, e);
			return auditId;
		}

		return auditId;
	}

	/**
	 * Record a revocation that purged nothing (no operational rows existed).
	 * Still worth a row: it is the evidence the action was taken.
	 */
	public long auditOnly(String username, String clientUid, String certSubjectDn, String certSerial,
			String certHash, String revokedBy, Source source, String notes, boolean succeeded) {
		try (Connection con = ds().getConnection()) {
			return insertAudit(con, username, clientUid, certSubjectDn, certSerial, certHash,
					revokedBy, source, "{}", notes, succeeded);
		} catch (Exception e) {
			logger.error("could not write revocation audit row for {}", username, e);
			return -1;
		}
	}

	/**
	 * Collect every device UID belonging to a user.
	 *
	 * <p>Both tables are consulted, not just client_endpoint. A user who was
	 * invited to a mission but never connected — or whose client_endpoint rows
	 * were already cleaned up by hand — has a mission_subscription and nothing
	 * else. Resolving UIDs from client_endpoint alone silently finds nothing for
	 * them, and the revocation quietly leaves the subscription (and its bearer
	 * token) in place, which is exactly the failure this class exists to prevent.
	 */
	private List<String> resolveUids(Connection con, String username, String clientUid) throws Exception {
		List<String> uids = new ArrayList<>();
		if (clientUid != null && !clientUid.isEmpty()) {
			uids.add(clientUid);
		}
		if (username != null && !username.isEmpty()) {
			collectUids(con, "SELECT DISTINCT uid FROM client_endpoint WHERE lower(username) = lower(?)",
					username, uids);
			collectUids(con, "SELECT DISTINCT client_uid FROM mission_subscription WHERE lower(username) = lower(?)",
					username, uids);
		}
		return uids;
	}

	private void collectUids(Connection con, String sql, String username, List<String> uids) throws Exception {
		try (PreparedStatement ps = con.prepareStatement(sql)) {
			ps.setString(1, username);
			try (ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
					String uid = rs.getString(1);
					if (uid != null && !uid.isEmpty() && !uids.contains(uid)) {
						uids.add(uid);
					}
				}
			}
		}
	}

	private String snapshotRows(Connection con, String sql, List<String> uids) throws Exception {
		if (uids.isEmpty()) {
			return "[]";
		}
		StringBuilder out = new StringBuilder("[");
		try (PreparedStatement ps = con.prepareStatement(sql)) {
			ps.setArray(1, con.createArrayOf("varchar", uids.toArray()));
			try (ResultSet rs = ps.executeQuery()) {
				ResultSetMetaData md = rs.getMetaData();
				boolean firstRow = true;
				while (rs.next()) {
					if (!firstRow) {
						out.append(',');
					}
					firstRow = false;
					out.append('{');
					for (int i = 1; i <= md.getColumnCount(); i++) {
						if (i > 1) {
							out.append(',');
						}
						String col = md.getColumnLabel(i);
						Object val = rs.getObject(i);
						out.append(jsonString(col)).append(':');
						if (val == null) {
							out.append("null");
						} else if (REDACT_COLUMNS.contains(col.toLowerCase(Locale.ROOT))) {
							out.append(jsonString("sha256:" + sha256Prefix(String.valueOf(val))));
						} else {
							out.append(jsonString(String.valueOf(val)));
						}
					}
					out.append('}');
				}
			}
		}
		return out.append(']').toString();
	}

	private int countRows(Connection con, String sql, List<String> uids) throws Exception {
		if (uids.isEmpty()) {
			return 0;
		}
		try (PreparedStatement ps = con.prepareStatement(sql)) {
			ps.setArray(1, con.createArrayOf("varchar", uids.toArray()));
			try (ResultSet rs = ps.executeQuery()) {
				return rs.next() ? rs.getInt(1) : 0;
			}
		}
	}

	private int executePurge(Connection con, String sql, List<String> uids) throws Exception {
		if (uids.isEmpty()) {
			return 0;
		}
		try (PreparedStatement ps = con.prepareStatement(sql)) {
			ps.setArray(1, con.createArrayOf("varchar", uids.toArray()));
			return ps.executeUpdate();
		}
	}

	private long insertAudit(Connection con, String username, String clientUid, String certSubjectDn,
			String certSerial, String certHash, String revokedBy, Source source,
			String snapshotJson, String notes, boolean succeeded) {
		String sql = "INSERT INTO certificate_revocation_audit "
				+ "(username, client_uid, cert_subject_dn, cert_serial, cert_hash, revoked_by, revoked_via, "
				+ " succeeded, purged_rows, notes) "
				+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSONB), ?)";
		try (PreparedStatement ps = con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
			ps.setString(1, username);
			ps.setString(2, clientUid);
			ps.setString(3, certSubjectDn);
			ps.setString(4, certSerial);
			ps.setString(5, certHash);
			ps.setString(6, revokedBy);
			ps.setString(7, source.getValue());
			ps.setBoolean(8, succeeded);
			ps.setString(9, snapshotJson);
			ps.setString(10, notes);
			ps.executeUpdate();
			try (ResultSet keys = ps.getGeneratedKeys()) {
				return keys.next() ? keys.getLong(1) : -1;
			}
		} catch (Exception e) {
			logger.error("failed to insert revocation audit row for {}", username, e);
			return -1;
		}
	}

	private void markSucceeded(Connection con, long auditId, String notes) {
		String sql = "UPDATE certificate_revocation_audit SET succeeded = TRUE, notes = ? WHERE id = ?";
		try (PreparedStatement ps = con.prepareStatement(sql)) {
			ps.setString(1, notes);
			ps.setLong(2, auditId);
			ps.executeUpdate();
		} catch (Exception e) {
			logger.error("failed to mark revocation audit row {} succeeded", auditId, e);
		}
	}

	private static String sha256Prefix(String value) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes("UTF-8"));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < 8 && i < digest.length; i++) {
				sb.append(String.format("%02x", digest[i]));
			}
			return sb.toString();
		} catch (Exception e) {
			return "unavailable";
		}
	}

	private static String toJsonArray(List<String> values) {
		StringBuilder sb = new StringBuilder("[");
		for (int i = 0; i < values.size(); i++) {
			if (i > 0) {
				sb.append(',');
			}
			sb.append(jsonString(values.get(i)));
		}
		return sb.append(']').toString();
	}

	private static String jsonString(String raw) {
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < raw.length(); i++) {
			char c = raw.charAt(i);
			switch (c) {
				case '"':  sb.append("\\\""); break;
				case '\\': sb.append("\\\\"); break;
				case '\n': sb.append("\\n");  break;
				case '\r': sb.append("\\r");  break;
				case '\t': sb.append("\\t");  break;
				default:
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					} else {
						sb.append(c);
					}
			}
		}
		return sb.append('"').toString();
	}
}
