CREATE TABLE ct_log_memberships (
  provider TEXT NOT NULL REFERENCES ct_log_lists(provider),
  log_url TEXT NOT NULL,
  PRIMARY KEY (provider, log_url)
);

UPDATE ct_log_lists SET etag = NULL, checked_at = NULL;
