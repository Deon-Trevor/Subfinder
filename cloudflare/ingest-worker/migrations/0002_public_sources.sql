CREATE TABLE IF NOT EXISTS public_source_state (
  source_id TEXT PRIMARY KEY CHECK (source_id IN ('iana-root', 'cisa-gov')),
  digest TEXT,
  etag TEXT,
  object_key TEXT,
  checked_at TEXT,
  next_run_at TEXT NOT NULL,
  lease_until TEXT,
  error TEXT
);

INSERT OR IGNORE INTO public_source_state(source_id, next_run_at)
VALUES ('iana-root', '1970-01-01T00:00:00.000Z');

INSERT OR IGNORE INTO public_source_state(source_id, next_run_at)
VALUES ('cisa-gov', '1970-01-01T00:00:00.000Z');
