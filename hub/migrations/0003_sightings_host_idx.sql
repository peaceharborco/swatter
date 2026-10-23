-- sightings is keyed (ip, host): every per-host query — /purge's
-- `DELETE ... WHERE host = ?` and the per-host live-row quota's
-- `COUNT(*) ... WHERE host = ? AND last_seen > ?` — was a full table scan.
CREATE INDEX ix_sightings_host_seen ON sightings(host, last_seen);
