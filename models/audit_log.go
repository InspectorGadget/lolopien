package models

import "time"

type AuditLog struct {
	ID        string      `db:"id"`
	UserID    *string     `db:"user_id"`   // nullable — SET NULL on user delete
	DeviceID  *string     `db:"device_id"` // nullable — SET NULL on device delete
	Action    AuditAction `db:"action"`
	Metadata  []byte      `db:"metadata"` // JSONB
	CreatedAt time.Time   `db:"created_at"`
}

// AuditAction is a typed string for the action field to prevent typos.
type AuditAction string

const (
	ActionDeviceRegistered AuditAction = "device_registered"
	ActionConfigDownloaded AuditAction = "config_downloaded"
	ActionDeviceRevoked    AuditAction = "device_revoked"
	ActionUserRegistered   AuditAction = "user_registered"
)
