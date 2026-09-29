ALTER TABLE czds_zones ADD COLUMN last_attempt_at TEXT;

CREATE INDEX IF NOT EXISTS czds_zones_attempts
ON czds_zones(enabled, last_completed_at, last_attempt_at, zone);
