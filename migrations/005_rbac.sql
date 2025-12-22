CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE scopes (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE role_scopes (
    role_id INTEGER REFERENCES roles(id),
    scope_id INTEGER REFERENCES scopes(id),
    PRIMARY KEY (role_id, scope_id)
);

ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id);
