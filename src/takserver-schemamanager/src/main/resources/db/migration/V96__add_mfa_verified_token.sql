-- Records that the admin holding a given access token has passed the TOTP gate.
--
-- The gate used to remember this only in the servlet session, which lives in one
-- server's memory. The access token itself is signed with the shared keystore and
-- stored in the shared database, so a login survives a move to another server
-- (blue/green cutover, task replacement), but the MFA stamp did not, and every
-- admin was sent back to the verify page. Keeping the stamp here, next to the
-- token, lets any server honour it.
--
-- Only a SHA-256 of the token is stored; it cannot be used to authenticate.
-- expires_at bounds the row's lifetime for cleanup. A row whose token has
-- expired or been revoked is harmless: the gate is only consulted after the
-- token has been authenticated.
CREATE TABLE IF NOT EXISTS mfa_verified_token (
    token_sha256  CHAR(64)     PRIMARY KEY,
    username      VARCHAR(255) NOT NULL,
    verified_at   TIMESTAMP    WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP    WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mfa_verified_token_expires_at ON mfa_verified_token(expires_at);
