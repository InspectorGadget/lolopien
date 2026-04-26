package controllers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/InspectorGadget/lolopien/config"
	"github.com/InspectorGadget/lolopien/services/encrypt"
	"github.com/InspectorGadget/lolopien/services/peersync"
	"github.com/aws/smithy-go"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler bundles the application dependencies that all controller methods need.
// Wire it in main.go and pass it to the router.
type Handler struct {
	cfg      *config.Config
	db       *pgxpool.Pool
	client   *http.Client
	encrypt  *encrypt.Service
	peersync *peersync.Service
}

// NewHandler constructs a Handler with all required dependencies.
func NewHandler(cfg *config.Config, db *pgxpool.Pool, enc *encrypt.Service, ps *peersync.Service) *Handler {
	return &Handler{
		cfg:      cfg,
		db:       db,
		client:   &http.Client{Timeout: 15 * time.Second},
		encrypt:  enc,
		peersync: ps,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Cognito shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func (h *Handler) cognitoEndpoint() string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/", h.cfg.AWSRegion)
}

func (h *Handler) computeSecretHash(username string) string {
	if h.cfg.CognitoClientSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(h.cfg.CognitoClientSecret))
	_, _ = mac.Write([]byte(username + h.cfg.CognitoClientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ─────────────────────────────────────────────────────────────────────────────
// Cognito error types
// ─────────────────────────────────────────────────────────────────────────────

type cognitoErrorResponse struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

type cognitoAttributePair struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

func mapRegisterStatusCode(cognitoType string) int {
	switch {
	case strings.Contains(cognitoType, "UsernameExistsException"):
		return http.StatusConflict
	case strings.Contains(cognitoType, "InvalidPasswordException"),
		strings.Contains(cognitoType, "InvalidParameterException"),
		strings.Contains(cognitoType, "CodeMismatchException"):
		return http.StatusBadRequest
	case strings.Contains(cognitoType, "TooManyRequestsException"),
		strings.Contains(cognitoType, "LimitExceededException"):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

func mapLoginStatusCode(cognitoType string) int {
	switch {
	case strings.Contains(cognitoType, "NotAuthorizedException"),
		strings.Contains(cognitoType, "UserNotFoundException"):
		return http.StatusUnauthorized
	case strings.Contains(cognitoType, "UserNotConfirmedException"),
		strings.Contains(cognitoType, "PasswordResetRequiredException"):
		return http.StatusForbidden
	case strings.Contains(cognitoType, "TooManyRequestsException"),
		strings.Contains(cognitoType, "LimitExceededException"):
		return http.StatusTooManyRequests
	case strings.Contains(cognitoType, "InvalidParameterException"):
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

func cognitoMessage(errResp cognitoErrorResponse) string {
	if msg := strings.TrimSpace(errResp.Message); msg != "" {
		return msg
	}
	if t := strings.TrimSpace(errResp.Type); t != "" {
		parts := strings.Split(t, "#")
		return parts[len(parts)-1]
	}
	return "cognito request failed"
}

// ─────────────────────────────────────────────────────────────────────────────
// General helpers
// ─────────────────────────────────────────────────────────────────────────────

func strPtr(s string) *string { return &s }

func awsErrorMessage(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("%s: %s", apiErr.ErrorCode(), apiErr.ErrorMessage())
	}
	return err.Error()
}
