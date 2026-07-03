-- offenders: NO host_count (derived at read time). Decay + metadata only.
CREATE TABLE offenders (
  ip         TEXT PRIMARY KEY,          -- IP or CIDR
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  last_host  TEXT,
  category   TEXT,
  expires    INTEGER NOT NULL
);
CREATE INDEX ix_offenders_expires ON offenders(expires);

CREATE TABLE sightings (
  ip        TEXT NOT NULL,
  host      TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (ip, host)
);
CREATE INDEX ix_sightings_seen ON sightings(last_seen);

-- registry: only enrolled host_ids count toward host_count.
CREATE TABLE hosts (
  host        TEXT PRIMARY KEY,
  enrolled_at INTEGER NOT NULL,
  label       TEXT
);
