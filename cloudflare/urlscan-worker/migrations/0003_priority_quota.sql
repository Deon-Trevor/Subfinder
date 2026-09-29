ALTER TABLE provider_quota ADD COLUMN priority_used INTEGER NOT NULL DEFAULT 0
  CHECK (priority_used >= 0);
