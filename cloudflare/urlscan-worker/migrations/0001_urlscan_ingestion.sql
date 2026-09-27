CREATE TABLE IF NOT EXISTS urlscan_sources (
  apex TEXT PRIMARY KEY,
  cursor TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  next_run_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS urlscan_jobs (
  job_id TEXT PRIMARY KEY,
  apex TEXT NOT NULL REFERENCES urlscan_sources(apex),
  cursor TEXT,
  state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'complete', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  quota_day TEXT,
  quota_charged INTEGER NOT NULL DEFAULT 0 CHECK (quota_charged IN (0, 1)),
  entry_count INTEGER,
  hostname_count INTEGER,
  object_key TEXT,
  next_cursor TEXT,
  error TEXT,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_quota (
  provider TEXT NOT NULL,
  quota_day TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0),
  PRIMARY KEY (provider, quota_day)
);

CREATE INDEX IF NOT EXISTS urlscan_sources_due
ON urlscan_sources(enabled, next_run_at, apex);

CREATE INDEX IF NOT EXISTS urlscan_jobs_state_created
ON urlscan_jobs(state, created_at);
