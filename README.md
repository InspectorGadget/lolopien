# lolopien

A VPN-as-a-Service backend built in Go. Users register devices, receive a WireGuard `.conf` they can import immediately, and the controller automatically syncs the peer list on the EC2 instance — no SSH required.

## Architecture

```
Client → Gin HTTP API → AWS Cognito (auth)
                      → PostgreSQL (state)
                      → AWS KMS (device key encryption)
                      → AWS SSM Run Command → EC2 / WireGuard
                      → AWS Secrets Manager (server private key)
```

- **Auth** — Amazon Cognito user pool. Every authenticated route validates the Cognito JWT against the pool's JWKS endpoint (RS256, 1-hour cache).
- **Device keys** — The controller generates a Curve25519 keypair per device. The private key is envelope-encrypted with KMS (AES-256-GCM) and stored in PostgreSQL as `BYTEA`. The public key is stored plaintext.
- **VPN IP allocation** — The server's subnet (e.g. `10.8.0.0/24`) is walked from `.2` upward. `.1` is reserved for the server gateway. Soft-deleted peer IPs are never re-used.
- **Peer sync** — After any device registration or revocation, `peersync.SyncServer` queries all active peers, renders two config variants, and ships them to the EC2 instance via SSM `AWS-RunShellScript`:
  - **Full config** (`wg-quick` format) → `/etc/wireguard/wg0.conf` for persistence across reboots.
  - **Sync config** (kernel-only, no `Address`/`PostUp`/`PostDown`) → applied live with `wg syncconf` so the interface is never restarted.
- **Database** — PostgreSQL with `pgx/v5`. Migrations run automatically at startup from embedded SQL files in `db/migrations/`.

## Project Layout

```
.
├── config/           # Env var loading and validation
├── controllers/      # Gin handlers (register, login, me, devices, vpnconfig)
├── db/               # Connection pool, migration runner
│   └── migrations/   # SQL migration files (run in sorted order)
├── infra/
│   └── ec2-userdata.sh  # EC2 bootstrap script (WireGuard + SSM agent)
├── middleware/       # Cognito JWT auth, structured request logging
├── models/           # Plain Go structs for DB rows
├── services/
│   ├── encrypt/      # KMS envelope encryption / decryption
│   ├── peersync/     # WireGuard peer sync via SSM
│   └── wireguard/    # Keypair generation, client config, server config rendering
├── docker-compose.yml
├── .env.example
├── main.go
└── test.http         # VS Code REST Client test suite
```

## Prerequisites

- Go 1.22+
- Docker (for local PostgreSQL via `docker-compose`)
- An AWS account with the following configured:
  - Cognito User Pool + App Client
  - KMS symmetric key (Encrypt/Decrypt)
  - EC2 instance running the bootstrap script with an IAM role that allows `ssm:SendCommand`
  - Secrets Manager secret holding the WireGuard server private key
  - IAM credentials available to the Go process (env vars, instance profile, or `~/.aws/credentials`)

## Local Setup

**1. Clone and install dependencies**

```bash
git clone https://github.com/InspectorGadget/lolopien
cd lolopien
go mod download
```

**2. Start PostgreSQL**

```bash
docker-compose up -d
```

**3. Configure environment**

```bash
cp .env.example .env
# Edit .env with your real values
```

Required variables:

| Variable                | Description                                          |
| ----------------------- | ---------------------------------------------------- |
| `AWS_REGION`            | AWS region (e.g. `ap-southeast-1`)                   |
| `COGNITO_USER_POOL_ID`  | Cognito user pool ID                                 |
| `COGNITO_CLIENT_ID`     | Cognito app client ID                                |
| `COGNITO_CLIENT_SECRET` | App client secret (leave blank if none)              |
| `KMS_KEY_ARN`           | ARN of the KMS key for device private key encryption |
| `DATABASE_URL`          | PostgreSQL connection string                         |
| `PORT`                  | HTTP listen port (default `8080`)                    |

**4. Run**

```bash
go run .
```

Migrations run automatically on startup. The server is ready when you see `"database ready"` and `"server starting"` in the logs.

## EC2 / WireGuard Setup

Run `infra/ec2-userdata.sh` as EC2 user data on an Ubuntu 22.04 LTS instance. It will:

1. Install `wireguard`, `wireguard-tools`, and `iptables`
2. Enable IPv4/IPv6 kernel forwarding
3. Generate a WireGuard server keypair at `/etc/wireguard/private.key` and `/etc/wireguard/public.key`
4. Write an initial `wg0.conf` with the correct network interface auto-detected (supports both `ens5` on Nitro and `eth0` on older instances)
5. Enable and start `wg-quick@wg0`
6. Ensure the SSM agent is running

After the instance boots:

1. Copy the public key from `/etc/wireguard/public.key`
2. Store the private key in AWS Secrets Manager — note the ARN
3. Insert a row into `vpn_servers`:

```sql
INSERT INTO vpn_servers (region, endpoint, public_key, subnet, ec2_instance_id, secret_arn)
VALUES (
  'ap-southeast-1',
  '<public-ip>:51820',
  '<server-public-key>',
  '10.8.0.0/24',
  'i-<instance-id>',
  'arn:aws:secretsmanager:...'
);
```

The EC2 security group needs **no inbound SSH**. SSM handles all remote access. Required inbound rules: UDP 51820 (WireGuard clients).

## API

All `/v1/*` routes require `Authorization: Bearer <access_token>`.

| Method   | Path                        | Description                                  |
| -------- | --------------------------- | -------------------------------------------- |
| `GET`    | `/ping`                     | Health check                                 |
| `POST`   | `/register`                 | Create a Cognito + DB user                   |
| `POST`   | `/login`                    | Authenticate, returns Cognito tokens         |
| `GET`    | `/v1/me`                    | Authenticated user profile                   |
| `POST`   | `/v1/devices`               | Register a device, returns WireGuard `.conf` |
| `GET`    | `/v1/devices`               | List active devices                          |
| `DELETE` | `/v1/devices/:id`           | Revoke a device                              |
| `GET`    | `/v1/vpn/config/:device_id` | Re-download `.conf` for a device             |

### Register a device

```http
POST /v1/devices
Authorization: Bearer <token>
Content-Type: application/json

{"name": "My MacBook"}
```

Response:

```json
{
  "device_id": "...",
  "name": "My MacBook",
  "public_key": "...",
  "vpn_ip": "10.8.0.2",
  "config": "[Interface]\nPrivateKey = ...\n..."
}
```

Save the `config` value to a `.conf` file and import it into any WireGuard client. The peer is added to the EC2 instance automatically — no manual `wg set` needed.

If peer sync fails (SSM error, etc.) the device is still saved and the response includes the header `X-Sync-Warning: peer sync pending`. The sync can be retried without data loss.

## Database Schema

Five tables: `users`, `vpn_servers`, `devices`, `peers`, `audit_logs`. Key design points:

- Devices and peers use **soft deletes** (`is_active = FALSE`). Revoked VPN IPs are never re-issued.
- `peers.vpn_ip` is PostgreSQL `INET` type. Always use `host(vpn_ip)` to extract the bare IP string without the prefix length.
- `devices.private_key_enc` is `BYTEA`. Wire format: `[4B: enc-key-len][KMS-encrypted data key][nonce || AES-GCM ciphertext]`.
- `vpn_servers.subnet` is PostgreSQL `CIDR`. Cast to text with `subnet::text`.

## Testing

`test.http` contains a complete test suite for the VS Code REST Client, covering registration, login, validation errors, device CRUD, config download, and revocation. Run requests top-to-bottom for a full happy-path flow. Set `@accessToken` from the login response before running authenticated requests.
