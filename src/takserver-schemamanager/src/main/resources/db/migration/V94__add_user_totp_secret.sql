-- Per-user TOTP secret for the admin web UI MFA gate.
-- Self-enrolled on first successful password login when no row exists.
-- Reset is only available via the operator CLI (see Taskfile.yml mfa-reset);
-- the admin web portal intentionally does not expose a reset button so a
-- compromised in-app session cannot reset another admin's second factor.
CREATE TABLE IF NOT EXISTS user_totp_secret (
    username      VARCHAR(255) PRIMARY KEY,
    secret_b32    VARCHAR(64)  NOT NULL,
    enrolled      BOOLEAN      NOT NULL DEFAULT FALSE,
    enrolled_at   TIMESTAMP    WITH TIME ZONE,
    last_used_at  TIMESTAMP    WITH TIME ZONE,
    created_at    TIMESTAMP    WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_totp_secret_enrolled ON user_totp_secret(enrolled);
