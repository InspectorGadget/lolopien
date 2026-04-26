package controllers

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/InspectorGadget/lolopien/middleware"
	"github.com/InspectorGadget/lolopien/models"
	"github.com/InspectorGadget/lolopien/services/wireguard"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/devices
// ─────────────────────────────────────────────────────────────────────────────

type RegisterDeviceRequest struct {
	Name string `json:"name" binding:"required,min=1,max=64"`
}

type RegisterDeviceResponse struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	VpnIP     string `json:"vpn_ip"`
	// Config is the full WireGuard .conf content, ready to import.
	Config string `json:"config"`
}

// RegisterDevice creates a new device for the authenticated user:
//  1. Generates a WireGuard keypair
//  2. Encrypts the private key with KMS
//  3. Allocates the next available VPN IP on the active server
//  4. Writes device + peer rows in a transaction
//  5. Syncs the updated peer list to EC2 via SSM
//  6. Returns the WireGuard .conf for the client to import
func (h *Handler) RegisterDevice(ctx *gin.Context) {
	var req RegisterDeviceRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sub, ok := middleware.GetUserSub(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	rctx := ctx.Request.Context()

	// Resolve internal user
	user, err := h.getUserBySub(rctx, sub)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Find the primary active VPN server
	server, err := h.getActiveServer(rctx)
	if err != nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "no active VPN server available"})
		return
	}

	// Generate WireGuard keypair
	kp, err := wireguard.GenerateKeypair()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate WireGuard keypair"})
		return
	}

	// Encrypt private key with KMS
	encPrivKey, err := h.encrypt.Encrypt(rctx, []byte(kp.PrivateKey))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt private key"})
		return
	}

	// Allocate next available VPN IP
	vpnIP, err := h.allocateVPNIP(rctx, server.ID, server.Subnet)
	if err != nil {
		ctx.JSON(http.StatusConflict, gin.H{"error": "no available VPN IPs: " + err.Error()})
		return
	}

	// Persist device + peer in a transaction
	var deviceID string
	err = pgx.BeginTxFunc(rctx, h.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		err := tx.QueryRow(rctx,
			`INSERT INTO devices (user_id, name, public_key, private_key_enc)
			 VALUES ($1, $2, $3, $4)
			 RETURNING id::text`,
			user.ID, req.Name, kp.PublicKey, encPrivKey,
		).Scan(&deviceID)
		if err != nil {
			return fmt.Errorf("inserting device: %w", err)
		}

		_, err = tx.Exec(rctx,
			`INSERT INTO peers (device_id, server_id, vpn_ip)
			 VALUES ($1, $2, $3::inet)`,
			deviceID, server.ID, vpnIP,
		)
		if err != nil {
			return fmt.Errorf("inserting peer: %w", err)
		}

		_, err = tx.Exec(rctx,
			`INSERT INTO audit_logs (user_id, device_id, action, metadata)
			 VALUES ($1, $2, $3, $4)`,
			user.ID, deviceID, models.ActionDeviceRegistered,
			fmt.Sprintf(`{"vpn_ip":"%s","server_id":"%s"}`, vpnIP, server.ID),
		)
		return err
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save device: " + err.Error()})
		return
	}

	// Sync peers to EC2 (best-effort — device is already saved)
	if syncErr := h.peersync.SyncServer(rctx, server.ID); syncErr != nil {
		slog.Error("peer sync failed", "server_id", server.ID, "error", syncErr)
		ctx.Header("X-Sync-Warning", "peer sync pending")
	} else {
		slog.Info("peer sync succeeded", "server_id", server.ID)
	}

	// Build client .conf
	_, network, _ := net.ParseCIDR(server.Subnet)
	ones, _ := network.Mask.Size()
	conf := wireguard.ClientConfig(wireguard.ClientConfigParams{
		DevicePrivateKey: kp.PrivateKey,
		DeviceVpnIP:      vpnIP,
		SubnetMask:       fmt.Sprintf("%d", ones),
		ServerPublicKey:  server.PublicKey,
		ServerEndpoint:   server.Endpoint,
	})

	ctx.JSON(http.StatusCreated, RegisterDeviceResponse{
		DeviceID:  deviceID,
		Name:      req.Name,
		PublicKey: kp.PublicKey,
		VpnIP:     vpnIP,
		Config:    conf,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/devices
// ─────────────────────────────────────────────────────────────────────────────

type DeviceSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	VpnIP     string `json:"vpn_ip,omitempty"`
	CreatedAt string `json:"created_at"`
}

// ListDevices returns all active devices belonging to the authenticated user.
func (h *Handler) ListDevices(ctx *gin.Context) {
	sub, ok := middleware.GetUserSub(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	rctx := ctx.Request.Context()
	user, err := h.getUserBySub(rctx, sub)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	rows, err := h.db.Query(rctx,
		`SELECT d.id::text, d.name, d.public_key,
		        COALESCE(host(p.vpn_ip), ''), d.created_at
		 FROM devices d
		 LEFT JOIN peers p ON p.device_id = d.id AND p.is_active = TRUE
		 WHERE d.user_id = $1 AND d.is_active = TRUE
		 ORDER BY d.created_at DESC`,
		user.ID,
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list devices"})
		return
	}
	defer rows.Close()

	var devices []DeviceSummary
	for rows.Next() {
		var d DeviceSummary
		var createdAt interface{}
		if err := rows.Scan(&d.ID, &d.Name, &d.PublicKey, &d.VpnIP, &createdAt); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read devices"})
			return
		}
		if t, ok := createdAt.(interface{ Format(string) string }); ok {
			d.CreatedAt = t.Format("2006-01-02T15:04:05Z07:00")
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read devices"})
		return
	}

	if devices == nil {
		devices = []DeviceSummary{}
	}
	ctx.JSON(http.StatusOK, gin.H{"devices": devices})
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /v1/devices/:id
// ─────────────────────────────────────────────────────────────────────────────

// RevokeDevice soft-deletes a device and its peer, then re-syncs the server.
func (h *Handler) RevokeDevice(ctx *gin.Context) {
	deviceID := ctx.Param("id")

	sub, ok := middleware.GetUserSub(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	rctx := ctx.Request.Context()
	user, err := h.getUserBySub(rctx, sub)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Verify ownership
	var serverID string
	err = h.db.QueryRow(rctx,
		`SELECT p.server_id::text
		 FROM devices d
		 JOIN peers p ON p.device_id = d.id
		 WHERE d.id = $1 AND d.user_id = $2 AND d.is_active = TRUE`,
		deviceID, user.ID,
	).Scan(&serverID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	// Soft-delete device and peer in a transaction
	err = pgx.BeginTxFunc(rctx, h.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		_, err := tx.Exec(rctx,
			`UPDATE devices SET is_active = FALSE, updated_at = NOW() WHERE id = $1`,
			deviceID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(rctx,
			`UPDATE peers SET is_active = FALSE, updated_at = NOW() WHERE device_id = $1`,
			deviceID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(rctx,
			`INSERT INTO audit_logs (user_id, device_id, action)
			 VALUES ($1, $2, $3)`,
			user.ID, deviceID, models.ActionDeviceRevoked)
		return err
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke device"})
		return
	}

	// Sync peers to EC2
	if syncErr := h.peersync.SyncServer(rctx, serverID); syncErr != nil {
		slog.Error("peer sync failed on revoke", "server_id", serverID, "device_id", deviceID, "error", syncErr)
		ctx.Header("X-Sync-Warning", "peer sync pending")
	} else {
		slog.Info("peer sync succeeded on revoke", "server_id", serverID)
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "device revoked"})
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) getActiveServer(ctx context.Context) (*models.VPNServer, error) {
	s := &models.VPNServer{}
	err := h.db.QueryRow(ctx,
		`SELECT id::text, region, endpoint, public_key, subnet::text,
		        ec2_instance_id, secret_arn, is_active, created_at, updated_at
		 FROM vpn_servers
		 WHERE is_active = TRUE
		 ORDER BY created_at
		 LIMIT 1`,
	).Scan(
		&s.ID, &s.Region, &s.Endpoint, &s.PublicKey, &s.Subnet,
		&s.EC2InstanceID, &s.SecretARN, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// allocateVPNIP finds the lowest unused IP in the server's subnet.
// The first host address (.1) is reserved for the server gateway.
func (h *Handler) allocateVPNIP(ctx context.Context, serverID, subnet string) (string, error) {
	// Fetch all currently allocated IPs for this server
	rows, err := h.db.Query(ctx,
		`SELECT host(vpn_ip) FROM peers WHERE server_id = $1`,
		serverID,
	)
	if err != nil {
		return "", fmt.Errorf("querying allocated IPs: %w", err)
	}
	defer rows.Close()

	taken := make(map[string]bool)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return "", err
		}
		taken[ip] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Walk the subnet from .2 upward, skipping taken IPs
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("parsing subnet %s: %w", subnet, err)
	}

	// Start at network base + 2 (base+1 = server gateway)
	candidate := cloneIP(network.IP)
	incrementIP(candidate, 2)

	for network.Contains(candidate) {
		// Skip broadcast (all host bits set)
		if isBroadcast(candidate, network) {
			break
		}
		ipStr := candidate.String()
		if !taken[ipStr] {
			return ipStr, nil
		}
		incrementIP(candidate, 1)
	}

	return "", fmt.Errorf("subnet %s is full", subnet)
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP, n int) {
	for i := len(ip) - 1; i >= 0 && n > 0; i-- {
		val := int(ip[i]) + n
		ip[i] = byte(val & 0xff)
		n = val >> 8
	}
}

func isBroadcast(ip net.IP, network *net.IPNet) bool {
	broadcast := make(net.IP, len(network.IP))
	for i := range network.IP {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}
