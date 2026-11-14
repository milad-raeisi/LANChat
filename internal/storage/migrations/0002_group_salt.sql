-- LANChat schema version 2: bind group IDs to their owner's key.
-- The salt is part of the derivation
-- group_id = SHA-256("LANChat group id v1" || owner SPKI || salt)[:16],
-- which prevents another member from claiming an existing group ID.
ALTER TABLE groups ADD COLUMN salt TEXT NOT NULL DEFAULT '';

-- Unpaired identities are no longer persisted (only peers that were paired
-- at some point are stored); drop rows written by earlier builds.
DELETE FROM peers WHERE trust = 'unknown';
