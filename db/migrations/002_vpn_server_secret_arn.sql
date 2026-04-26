-- Add secret_arn to vpn_servers.
-- This column holds the AWS Secrets Manager ARN for the server's WireGuard
-- private key. The controller fetches it when building the full wg0.conf
-- for SSM sync, so the private key never needs to live in the database.
ALTER TABLE vpn_servers
    ADD COLUMN IF NOT EXISTS secret_arn TEXT NOT NULL DEFAULT '';
