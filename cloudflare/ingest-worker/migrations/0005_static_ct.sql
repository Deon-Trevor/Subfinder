ALTER TABLE ct_sources ADD COLUMN protocol TEXT NOT NULL DEFAULT 'rfc6962'
CHECK (protocol IN ('rfc6962', 'static'));

INSERT OR IGNORE INTO ct_sources(
  source_id, log_url, next_index, enabled, updated_at,
  discovered, cursor_initialized, protocol
) VALUES (
  'static-willow-2026h2', 'https://mon.willow.ct.letsencrypt.org/2026h2',
  0, 0, '1970-01-01T00:00:00.000Z', 0, 0, 'static'
);
