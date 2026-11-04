CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    csrf       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT    NOT NULL,
    hash         TEXT    NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE TABLE images (
    id          TEXT PRIMARY KEY,
    delete_hash TEXT    NOT NULL UNIQUE,
    storage     TEXT    NOT NULL,
    size_bytes  INTEGER NOT NULL,
    width       INTEGER NOT NULL,
    height      INTEGER NOT NULL,
    token_id    TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER
);

CREATE INDEX images_created ON images (created_at);
CREATE INDEX images_expires ON images (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX sessions_expires ON sessions (expires_at);
