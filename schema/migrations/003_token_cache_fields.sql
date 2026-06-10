ALTER TABLE zia.token_usage ADD COLUMN IF NOT EXISTS cache_creation_tokens UInt32 DEFAULT 0;
ALTER TABLE zia.token_usage ADD COLUMN IF NOT EXISTS cache_read_tokens UInt32 DEFAULT 0;
