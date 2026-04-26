package models

import "time"

type Peer struct {
	ID        string    `db:"id"`
	DeviceID  string    `db:"device_id"`
	ServerID  string    `db:"server_id"`
	VpnIP     string    `db:"vpn_ip"` // e.g. "10.8.0.5"
	IsActive  bool      `db:"is_active"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}
