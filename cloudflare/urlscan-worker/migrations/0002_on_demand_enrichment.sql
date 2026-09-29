ALTER TABLE urlscan_jobs ADD COLUMN subject TEXT;
ALTER TABLE urlscan_jobs ADD COLUMN origin TEXT NOT NULL DEFAULT 'scheduled'
  CHECK (origin IN ('scheduled', 'enrichment'));

CREATE UNIQUE INDEX IF NOT EXISTS urlscan_one_active_apex
ON urlscan_jobs(apex) WHERE state IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS urlscan_enrichment_daily_charge
ON urlscan_jobs(origin, quota_day, quota_charged);
