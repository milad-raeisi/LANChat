-- LANChat schema version 1.
-- All timestamps are UTC Unix milliseconds.

CREATE TABLE peers (
    peer_id      TEXT PRIMARY KEY,
    public_key   BLOB NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    device_name  TEXT NOT NULL DEFAULT '',
    trust        TEXT NOT NULL DEFAULT 'unknown' CHECK (trust IN ('unknown', 'trusted', 'revoked')),
    verified     INTEGER NOT NULL DEFAULT 0,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    trusted_at   INTEGER NOT NULL DEFAULT 0,
    last_address TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE conversations (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('room', 'direct', 'group')),
    title         TEXT NOT NULL,
    peer_id       TEXT NOT NULL DEFAULT '',
    joined        INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    last_read_seq INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE groups (
    group_id        TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL UNIQUE REFERENCES conversations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    owner_id        TEXT NOT NULL,
    version         INTEGER NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('active', 'left', 'removed', 'disbanded'))
) STRICT;

CREATE TABLE group_members (
    group_id     TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    peer_id      TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, peer_id)
) STRICT;

CREATE TABLE messages (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT NOT NULL,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id       TEXT NOT NULL,
    sender_name     TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'text' CHECK (kind IN ('text', 'system')),
    body            TEXT NOT NULL,
    sent_at         INTEGER NOT NULL,
    received_at     INTEGER NOT NULL,
    outgoing        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (sender_id, message_id)
) STRICT;

CREATE INDEX idx_messages_conversation ON messages (conversation_id, seq);

CREATE TABLE deliveries (
    message_seq INTEGER NOT NULL REFERENCES messages(seq) ON DELETE CASCADE,
    peer_id     TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'delivered', 'failed')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    error       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (message_seq, peer_id)
) STRICT;

CREATE INDEX idx_deliveries_peer_status ON deliveries (peer_id, status);

CREATE TABLE transfers (
    transfer_id TEXT PRIMARY KEY,
    peer_id     TEXT NOT NULL,
    direction   TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    file_name   TEXT NOT NULL,
    size        INTEGER NOT NULL,
    path        TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL,
    sha256      TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

INSERT INTO conversations (id, kind, title, joined, created_at)
VALUES ('room:general', 'room', 'general', 1, CAST(strftime('%s', 'now') AS INTEGER) * 1000);
