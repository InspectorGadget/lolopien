package models

import "time"

type VPNServer struct {
	ID            string    `db:"id"`
	Region        string    `db:"region"`     // e.g. "us-east-1"
	Endpoint      string    `db:"endpoint"`   // e.g. "1.2.3.4:51820"
	PublicKey     string    `db:"public_key"` // WireGuard server public key
	Subnet        string    `db:"subnet"`     // CIDR, e.g. "10.8.0.0/24"
	EC2InstanceID string    `db:"ec2_instance_id"`
	SecretARN     string    `db:"secret_arn"` // Secrets Manager ARN for the WireGuard private key
	IsActive      bool      `db:"is_active"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}
