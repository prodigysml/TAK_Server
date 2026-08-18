-- Durable audit trail for certificate revocations.
--
-- Revoking a user is destructive by nature: the cert serial goes to the CRL, the
-- account leaves UserAuthenticationFile.xml, and the operational rows that made
-- the user visible (client_endpoint, client_endpoint_event, mission_subscription)
-- are purged so a revoked callsign stops appearing in the admin UI as if still
-- connected. Without this table that purge would destroy the only record that the
-- user ever existed on the server.
--
-- The log-file audit appender is not a substitute: logs/ is a per-colour mount in
-- the blue/green deployment and rotates hourly, so a trail written there does not
-- survive a colour roll. This table lives in the shared database and is covered by
-- the normal snapshot schedule.
--
-- purged_rows holds a JSON snapshot of exactly what was deleted, captured BEFORE
-- the delete. Secrets are redacted on the way in: mission_subscription tokens are
-- bearer credentials, so only a SHA-256 prefix is retained (enough to correlate a
-- later log line with the row, useless for authenticating), and no password hash
-- from UserAuthenticationFile is ever copied here.
CREATE TABLE IF NOT EXISTS certificate_revocation_audit (
    id                BIGSERIAL PRIMARY KEY,
    revoked_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username          VARCHAR(255),
    client_uid        VARCHAR(255),
    cert_subject_dn   TEXT,
    cert_serial       VARCHAR(64),
    cert_hash         VARCHAR(255),
    -- Who performed it, and through which path ('admin-ui' or 'operator-cli').
    revoked_by        VARCHAR(255) NOT NULL,
    revoked_via       VARCHAR(32)  NOT NULL,
    -- TRUE only when every step (CRL write, account removal, row purge) succeeded.
    succeeded         BOOLEAN      NOT NULL DEFAULT FALSE,
    purged_rows       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    notes             TEXT
);

CREATE INDEX IF NOT EXISTS idx_cert_revocation_audit_username   ON certificate_revocation_audit(lower(username));
CREATE INDEX IF NOT EXISTS idx_cert_revocation_audit_revoked_at ON certificate_revocation_audit(revoked_at DESC);
CREATE INDEX IF NOT EXISTS idx_cert_revocation_audit_serial     ON certificate_revocation_audit(cert_serial);
