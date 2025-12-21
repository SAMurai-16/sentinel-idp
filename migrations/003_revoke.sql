CREATE TABLE revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT now()
);
