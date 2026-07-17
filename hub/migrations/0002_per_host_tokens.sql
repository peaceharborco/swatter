-- Per-host write tokens: bind write identity to a credential issued at enrollment
-- so a leaked token impersonates only ONE host, not the fleet (was: shared
-- SWARM_WRITE_TOKEN + body host_id). token_hash is the SHA-256 hex of the token;
-- the plaintext is returned once at /register and never stored. NULL = a host
-- enrolled before this feature (legacy write-token path still works for it until
-- it re-enrolls). UNIQUE so a token maps to exactly one host; SQLite/D1 allows
-- multiple NULLs, so un-migrated rows are unaffected.
ALTER TABLE hosts ADD COLUMN token_hash TEXT;
CREATE UNIQUE INDEX ix_hosts_token_hash ON hosts(token_hash);
