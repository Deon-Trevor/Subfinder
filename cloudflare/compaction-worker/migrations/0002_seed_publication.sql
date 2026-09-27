CREATE TABLE IF NOT EXISTS catalog_seeds (
  seed_id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('published', 'active')),
  candidate_root_key TEXT NOT NULL,
  candidate_root_sha256 TEXT NOT NULL,
  partition_count INTEGER NOT NULL CHECK (partition_count >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
