package peersync

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/InspectorGadget/lolopien/services/wireguard"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service orchestrates peer synchronisation for a single VPN server.
type Service struct {
	db      *pgxpool.Pool
	secrets *secretsmanager.Client
	ssm     *ssm.Client
}

// New creates a peersync.Service using the given AWS config and database pool.
func New(awsCfg aws.Config, db *pgxpool.Pool) *Service {
	return &Service{
		db:      db,
		secrets: secretsmanager.NewFromConfig(awsCfg),
		ssm:     ssm.NewFromConfig(awsCfg),
	}
}

// serverRow is an internal projection of the vpn_servers table.
type serverRow struct {
	id            string
	endpoint      string
	publicKey     string
	subnet        string
	ec2InstanceID string
	secretARN     string
}

// peerRow is an internal projection of the peers + devices join.
type peerRow struct {
	publicKey string
	vpnIP     string
}

// SyncServer rebuilds the full wg0.conf from the database and applies it to
// the EC2 instance via SSM Run Command. Call this after any peer change.
func (s *Service) SyncServer(ctx context.Context, serverID string) error {
	srv, err := s.fetchServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("fetching server %s: %w", serverID, err)
	}

	privKey, err := s.fetchSecret(ctx, srv.secretARN)
	if err != nil {
		return fmt.Errorf("fetching server private key: %w", err)
	}

	peers, err := s.fetchActivePeers(ctx, serverID)
	if err != nil {
		return fmt.Errorf("fetching active peers: %w", err)
	}

	// Derive the server's VPN IP (.1) and prefix length from the subnet
	serverVpnIP, mask, err := subnetGateway(srv.subnet)
	if err != nil {
		return fmt.Errorf("parsing subnet %s: %w", srv.subnet, err)
	}

	wgPeers := make([]wireguard.PeerEntry, len(peers))
	for i, p := range peers {
		wgPeers[i] = wireguard.PeerEntry{PublicKey: p.publicKey, VpnIP: p.vpnIP}
	}

	params := wireguard.ServerConfigParams{
		ServerPrivateKey: privKey,
		ServerVpnIP:      serverVpnIP,
		SubnetMask:       mask,
		Peers:            wgPeers,
	}

	// Full config (with wg-quick directives) for persistence on disk.
	// Stripped config (kernel-only) for wg syncconf.
	return s.pushConfig(ctx, srv.ec2InstanceID, wireguard.ServerConfig(params), wireguard.SyncConfConfig(params))
}

// ─────────────────────────────────────────────────────────────────────────────
// Database helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Service) fetchServer(ctx context.Context, serverID string) (serverRow, error) {
	var row serverRow
	err := s.db.QueryRow(ctx,
		`SELECT id::text, endpoint, public_key, subnet::text,
		        ec2_instance_id, secret_arn
		 FROM vpn_servers
		 WHERE id = $1 AND is_active = TRUE`,
		serverID,
	).Scan(&row.id, &row.endpoint, &row.publicKey, &row.subnet,
		&row.ec2InstanceID, &row.secretARN)
	return row, err
}

func (s *Service) fetchActivePeers(ctx context.Context, serverID string) ([]peerRow, error) {
	rows, err := s.db.Query(ctx,
		`SELECT d.public_key, host(p.vpn_ip)
		 FROM peers p
		 JOIN devices d ON d.id = p.device_id
		 WHERE p.server_id = $1 AND p.is_active = TRUE AND d.is_active = TRUE
		 ORDER BY p.vpn_ip`,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []peerRow
	for rows.Next() {
		var p peerRow
		if err := rows.Scan(&p.publicKey, &p.vpnIP); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Service) fetchSecret(ctx context.Context, arn string) (string, error) {
	out, err := s.secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &arn,
	})
	if err != nil {
		return "", fmt.Errorf("GetSecretValue: %w", err)
	}
	if out.SecretString != nil {
		return strings.TrimSpace(*out.SecretString), nil
	}
	return "", fmt.Errorf("secret %s has no string value", arn)
}

// pushConfig writes both config variants to the EC2 instance:
//   - fullConf  → /etc/wireguard/wg0.conf  (wg-quick format, persists across reboots)
//   - syncConf  → /tmp/wg0-sync.conf       (kernel-only format, used with wg syncconf)
func (s *Service) pushConfig(ctx context.Context, instanceID, fullConf, syncConf string) error {
	safeFullConf := strings.ReplaceAll(fullConf, "'", "'\\''")
	safeSyncConf := strings.ReplaceAll(syncConf, "'", "'\\''")

	script := fmt.Sprintf(`set -e

cat > /etc/wireguard/wg0.conf << 'WGEOF'
%s
WGEOF
chmod 600 /etc/wireguard/wg0.conf

cat > /tmp/wg0-sync.conf << 'WGEOF'
%s
WGEOF
wg syncconf wg0 /tmp/wg0-sync.conf
rm -f /tmp/wg0-sync.conf
`, safeFullConf, safeSyncConf)

	_, err := s.ssm.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": {script},
		},
	})
	if err != nil {
		return fmt.Errorf("SSM SendCommand: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Network helpers
// ─────────────────────────────────────────────────────────────────────────────

func subnetGateway(cidr string) (gatewayIP, prefixLen string, err error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	_ = ip

	// Increment the network address by 1 to get the gateway
	gw := make(net.IP, len(network.IP))
	copy(gw, network.IP)
	gw[len(gw)-1]++

	ones, _ := network.Mask.Size()
	return gw.String(), fmt.Sprintf("%d", ones), nil
}
