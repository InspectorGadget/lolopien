-- Enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────
-- users
-- Mirrors Cognito identity. cognito_sub is the bridge key used
-- by the JWT middleware to resolve the internal user record.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cognito_sub TEXT        NOT NULL UNIQUE,
    email       TEXT        NOT NULL UNIQUE,
    username    TEXT        NOT NULL UNIQUE,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────
-- vpn_servers
-- One row per EC2 WireGuard instance. Designed for a single
-- server today; adding more regions means adding more rows.
-- The server private key lives in AWS Secrets Manager — only
-- the public key is stored here.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vpn_servers (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    region          TEXT        NOT NULL,
    endpoint        TEXT        NOT NULL,           -- e.g. "1.2.3.4:51820"
    public_key      TEXT        NOT NULL,           -- WireGuard server pubkey
    subnet          CIDR        NOT NULL,           -- e.g. 10.8.0.0/24
    ec2_instance_id TEXT        NOT NULL,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────
-- devices
-- A device is anything a user registers (phone, laptop, etc.).
-- The controller generates the WireGuard keypair and stores the
-- private key AES-encrypted with AWS KMS (envelope encryption).
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    public_key      TEXT        NOT NULL UNIQUE,
    private_key_enc BYTEA       NOT NULL,           -- KMS-encrypted private key
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────
-- peers
-- Active WireGuard peer assignment: device ↔ server ↔ VPN IP.
-- This table is the source of truth for wg syncconf. Setting
-- is_active = false removes the peer from the server on next sync.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS peers (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_id   UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    vpn_ip      INET        NOT NULL,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, vpn_ip)
);

-- ─────────────────────────────────────────────────────────────
-- audit_logs
-- Lightweight event trail. Not operational — just records what
-- happened and when. Flexible metadata column for future use.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
    device_id   UUID        REFERENCES devices(id) ON DELETE SET NULL,
    action      TEXT        NOT NULL,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────
-- Indexes
-- ─────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_devices_user_id      ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_peers_device_id      ON peers(device_id);
CREATE INDEX IF NOT EXISTS idx_peers_server_id      ON peers(server_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id   ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
