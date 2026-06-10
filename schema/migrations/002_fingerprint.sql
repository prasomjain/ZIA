-- Idempotent migration for existing Phase 1 deployments
ALTER TABLE zia.zero_day_alerts ADD COLUMN IF NOT EXISTS iocs Array(String) DEFAULT [];
ALTER TABLE zia.zero_day_alerts ADD COLUMN IF NOT EXISTS fingerprint String DEFAULT '';
