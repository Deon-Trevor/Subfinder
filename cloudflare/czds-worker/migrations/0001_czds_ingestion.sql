CREATE TABLE IF NOT EXISTS czds_zones (
  zone TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  last_completed_at TEXT,
  last_modified TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS czds_jobs (
  job_id TEXT PRIMARY KEY,
  zone TEXT NOT NULL REFERENCES czds_zones(zone),
  download_url TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'staged', 'complete', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  source_fingerprint TEXT,
  hostname_count INTEGER,
  delta_count INTEGER,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS czds_job_deltas (
  job_id TEXT NOT NULL REFERENCES czds_jobs(job_id),
  chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
  delta_id TEXT NOT NULL UNIQUE,
  object_key TEXT NOT NULL UNIQUE,
  record_count INTEGER NOT NULL CHECK (record_count > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (job_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS czds_jobs_state_created
ON czds_jobs(state, created_at);

CREATE INDEX IF NOT EXISTS czds_zones_refresh
ON czds_zones(enabled, last_completed_at, zone);
