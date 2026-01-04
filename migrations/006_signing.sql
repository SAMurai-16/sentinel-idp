CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    active BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now()
);
