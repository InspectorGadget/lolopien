package models

import "time"

type Device struct {
	ID            string    `db:"id"`
	UserID        string    `db:"user_id"`
	Name          string    `db:"name"`
	PublicKey     string    `db:"public_key"`
	PrivateKeyEnc []byte    `db:"private_key_enc"` // KMS-encrypted WireGuard private key
	IsActive      bool      `db:"is_active"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}
