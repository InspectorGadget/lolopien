package controllers

import (
	"fmt"
	"net"
	"net/http"

	"github.com/InspectorGadget/lolopien/middleware"
	"github.com/InspectorGadget/lolopien/services/wireguard"
	"github.com/gin-gonic/gin"
)

// GetConfig decrypts the device's private key and returns a fully rendered
// WireGuard .conf file as a downloadable attachment.
//
// GET /v1/vpn/config/:device_id
func (h *Handler) GetConfig(ctx *gin.Context) {
	deviceID := ctx.Param("device_id")

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

	// Fetch device, peer, and server in one join — enforce ownership
	var (
		deviceName    string
		publicKey     string
		privateKeyEnc []byte
		vpnIP         string
		serverPubKey  string
		serverEndpoint string
		serverSubnet  string
	)
	err = h.db.QueryRow(rctx,
		`SELECT d.name, d.public_key, d.private_key_enc,
		        host(p.vpn_ip),
		        s.public_key, s.endpoint, s.subnet::text
		 FROM devices d
		 JOIN peers p       ON p.device_id = d.id AND p.is_active = TRUE
		 JOIN vpn_servers s ON s.id = p.server_id AND s.is_active = TRUE
		 WHERE d.id = $1 AND d.user_id = $2 AND d.is_active = TRUE`,
		deviceID, user.ID,
	).Scan(&deviceName, &publicKey, &privateKeyEnc,
		&vpnIP, &serverPubKey, &serverEndpoint, &serverSubnet)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	// Decrypt the private key
	privKeyBytes, err := h.encrypt.Decrypt(rctx, privateKeyEnc)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt private key"})
		return
	}

	// Derive prefix length from server subnet
	_, network, _ := net.ParseCIDR(serverSubnet)
	ones, _ := network.Mask.Size()

	conf := wireguard.ClientConfig(wireguard.ClientConfigParams{
		DevicePrivateKey: string(privKeyBytes),
		DeviceVpnIP:      vpnIP,
		SubnetMask:       fmt.Sprintf("%d", ones),
		ServerPublicKey:  serverPubKey,
		ServerEndpoint:   serverEndpoint,
	})

	// Write audit log (best-effort)
	_, _ = h.db.Exec(rctx,
		`INSERT INTO audit_logs (user_id, device_id, action)
		 VALUES ($1, $2, $3)`,
		user.ID, deviceID, "config_downloaded",
	)

	filename := fmt.Sprintf("lolopien-%s.conf", sanitiseFilename(deviceName))
	ctx.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	ctx.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(conf))
}

// sanitiseFilename replaces characters that are unsafe in filenames with hyphens.
func sanitiseFilename(name string) string {
	out := make([]byte, len(name))
	for i := range name {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			out[i] = c
		} else {
			out[i] = '-'
		}
	}
	return string(out)
}
