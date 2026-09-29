UPDATE provider_quota
SET priority_used = (
  SELECT count(*) FROM urlscan_jobs
  WHERE origin = 'enrichment'
    AND quota_charged = 1
    AND quota_day = provider_quota.quota_day
)
WHERE provider = 'urlscan:breadth'
  AND priority_used < (
    SELECT count(*) FROM urlscan_jobs
    WHERE origin = 'enrichment'
      AND quota_charged = 1
      AND quota_day = provider_quota.quota_day
  );
