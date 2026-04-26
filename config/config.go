package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime configuration loaded from environment variables.
// The application will refuse to start if any required field is missing.
type Config struct {
	Port string

	// AWS
	AWSRegion string

	// Cognito — used by both auth handlers and the JWT middleware
	CognitoClientID     string
	CognitoClientSecret string // optional; omit if pool has no app secret
	CognitoUserPoolID   string

	// KMS — used for device private key envelope encryption
	KMSKeyARN string

	// Database
	DatabaseURL string
}

// Load reads environment variables, validates required fields, and returns a
// populated Config. Returns an error describing exactly which variable is missing.
func Load() (*Config, error) {
	region := strings.TrimSpace(os.Getenv("AWS_REGION"))
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
	}

	clientID := strings.TrimSpace(os.Getenv("COGNITO_CLIENT_ID"))
	userPoolID := strings.TrimSpace(os.Getenv("COGNITO_USER_POOL_ID"))
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	kmsKeyARN := strings.TrimSpace(os.Getenv("KMS_KEY_ARN"))

	var missing []string
	if region == "" {
		missing = append(missing, "AWS_REGION")
	}
	if clientID == "" {
		missing = append(missing, "COGNITO_CLIENT_ID")
	}
	if userPoolID == "" {
		missing = append(missing, "COGNITO_USER_POOL_ID")
	}
	if dbURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if kmsKeyARN == "" {
		missing = append(missing, "KMS_KEY_ARN")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	return &Config{
		Port:                port,
		AWSRegion:           region,
		CognitoClientID:     clientID,
		CognitoClientSecret: strings.TrimSpace(os.Getenv("COGNITO_CLIENT_SECRET")),
		CognitoUserPoolID:   userPoolID,
		KMSKeyARN:           kmsKeyARN,
		DatabaseURL:         dbURL,
	}, nil
}
