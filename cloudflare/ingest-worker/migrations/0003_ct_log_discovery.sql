ALTER TABLE ct_sources ADD COLUMN discovered INTEGER NOT NULL DEFAULT 0
CHECK (discovered IN (0, 1));

ALTER TABLE ct_sources ADD COLUMN cursor_initialized INTEGER NOT NULL DEFAULT 1
CHECK (cursor_initialized IN (0, 1));

ALTER TABLE ct_sources ADD COLUMN retry_at TEXT;
ALTER TABLE ct_sources ADD COLUMN last_error TEXT;

CREATE TABLE ct_log_lists (
  provider TEXT PRIMARY KEY CHECK (provider IN ('chrome', 'apple')),
  etag TEXT,
  checked_at TEXT
);

INSERT OR IGNORE INTO ct_log_lists(provider) VALUES ('chrome');
INSERT OR IGNORE INTO ct_log_lists(provider) VALUES ('apple');
