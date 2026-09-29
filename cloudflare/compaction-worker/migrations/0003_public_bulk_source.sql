PRAGMA defer_foreign_keys = on;

CREATE TABLE generation_fragments_backup AS
SELECT generation_id, delta_id, prefix, object_key, object_sha256,
       object_bytes, record_count, created_at
FROM generation_fragments;

DROP TABLE generation_fragments;

CREATE TABLE catalog_deltas_new (
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

INSERT INTO catalog_deltas_new (
  delta_id, source_kind, object_key, object_sha256, object_bytes, state,
  generation_id, record_count, error, created_at, updated_at
)
SELECT delta_id, source_kind, object_key, object_sha256, object_bytes, state,
       generation_id, record_count, error, created_at, updated_at
FROM catalog_deltas;

DROP TABLE catalog_deltas;
ALTER TABLE catalog_deltas_new RENAME TO catalog_deltas;

CREATE TABLE generation_fragments (
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

INSERT INTO generation_fragments (
  generation_id, delta_id, prefix, object_key, object_sha256,
  object_bytes, record_count, created_at
)
SELECT generation_id, delta_id, prefix, object_key, object_sha256,
       object_bytes, record_count, created_at
FROM generation_fragments_backup;

DROP TABLE generation_fragments_backup;

CREATE INDEX catalog_deltas_state_created
ON catalog_deltas(state, created_at, delta_id);

CREATE INDEX catalog_deltas_generation_state
ON catalog_deltas(generation_id, state, delta_id);
