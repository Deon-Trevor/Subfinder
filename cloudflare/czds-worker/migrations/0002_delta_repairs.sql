CREATE TABLE IF NOT EXISTS czds_delta_repairs (
  job_id TEXT NOT NULL,
  chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
  original_delta_id TEXT NOT NULL UNIQUE,
  original_object_key TEXT NOT NULL UNIQUE,
  original_record_count INTEGER NOT NULL CHECK (original_record_count > 0),
  original_document_sha256 TEXT NOT NULL,
  replacement_delta_id TEXT NOT NULL UNIQUE,
  replacement_object_key TEXT NOT NULL UNIQUE,
  replacement_record_count INTEGER NOT NULL CHECK (replacement_record_count > 0),
  replacement_document_sha256 TEXT NOT NULL,
  excluded_record_count INTEGER NOT NULL CHECK (excluded_record_count > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (job_id, chunk_index),
  FOREIGN KEY (job_id, chunk_index) REFERENCES czds_job_deltas(job_id, chunk_index)
);
