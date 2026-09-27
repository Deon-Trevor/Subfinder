CREATE TABLE IF NOT EXISTS ct_sources (
  source_id TEXT PRIMARY KEY,
  log_url TEXT NOT NULL UNIQUE,
  next_index INTEGER NOT NULL DEFAULT 0 CHECK (next_index >= 0),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_jobs (
  job_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES ct_sources(source_id),
  start_index INTEGER NOT NULL CHECK (start_index >= 0),
  end_index INTEGER NOT NULL CHECK (end_index >= start_index),
  state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'complete', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  entry_count INTEGER,
  hostname_count INTEGER,
  object_key TEXT,
  error TEXT,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source_id, start_index, end_index)
);

CREATE INDEX IF NOT EXISTS ingest_jobs_state_created
ON ingest_jobs(state, created_at);
