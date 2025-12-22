CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    parent_id UUID,
    created_at TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_refresh_token_hash ON refresh_tokens(token_hash);
