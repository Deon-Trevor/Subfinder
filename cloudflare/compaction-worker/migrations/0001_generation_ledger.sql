CREATE TABLE IF NOT EXISTS catalog_deltas (
  delta_id TEXT PRIMARY KEY,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('direct-ct', 'static-ct', 'urlscan', 'czds', 'public-bulk')),
  object_key TEXT NOT NULL UNIQUE,
  object_sha256 TEXT NOT NULL,
  object_bytes INTEGER NOT NULL CHECK (object_bytes > 0),
  state TEXT NOT NULL CHECK (state IN ('registered', 'assigned', 'mapped', 'failed')),
  generation_id TEXT REFERENCES catalog_generations(generation_id),
  record_count INTEGER NOT NULL CHECK (record_count >= 0),
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS catalog_generations (
  generation_id TEXT PRIMARY KEY,
  base_generation TEXT,
  state TEXT NOT NULL CHECK (state IN ('mapping', 'mapped', 'reducing', 'published', 'active', 'rolled_back', 'failed')),
  delta_count INTEGER NOT NULL CHECK (delta_count > 0),
  partition_count INTEGER NOT NULL DEFAULT 0 CHECK (partition_count >= 0),
  candidate_root_key TEXT,
  candidate_root_sha256 TEXT,
  previous_root_etag TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS catalog_one_mapping_generation
ON catalog_generations((1)) WHERE state = 'mapping';

CREATE TABLE IF NOT EXISTS generation_partitions (
  generation_id TEXT NOT NULL REFERENCES catalog_generations(generation_id),
  prefix TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('mapped', 'reducing', 'reduced', 'failed')),
  fragment_count INTEGER NOT NULL DEFAULT 0 CHECK (fragment_count >= 0),
  record_count INTEGER NOT NULL DEFAULT 0 CHECK (record_count >= 0),
  output_json TEXT,
  lease_token TEXT,
  lease_until TEXT,
  error TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (generation_id, prefix)
);

CREATE TABLE IF NOT EXISTS generation_fragments (
  generation_id TEXT NOT NULL REFERENCES catalog_generations(generation_id),
  delta_id TEXT NOT NULL REFERENCES catalog_deltas(delta_id),
  prefix TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  object_sha256 TEXT NOT NULL,
  object_bytes INTEGER NOT NULL CHECK (object_bytes > 0),
  record_count INTEGER NOT NULL CHECK (record_count > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (generation_id, delta_id, prefix)
);

CREATE INDEX IF NOT EXISTS catalog_deltas_state_created
ON catalog_deltas(state, created_at, delta_id);

CREATE INDEX IF NOT EXISTS catalog_deltas_generation_state
ON catalog_deltas(generation_id, state, delta_id);
