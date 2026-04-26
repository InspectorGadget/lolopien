package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/InspectorGadget/lolopien/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// contextKeyType prevents key collisions in gin.Context.
type contextKeyType string

const contextKeyUserSub contextKeyType = "user_sub"

// Auth validates Cognito JWTs and injects the user's Cognito sub into the
// request context. JWKS are fetched once and cached for 1 hour.
type Auth struct {
	cfg       *config.Config
	mu        sync.RWMutex
	keyCache  map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// NewAuth constructs an Auth middleware instance.
func NewAuth(cfg *config.Config) *Auth {
	return &Auth{
		cfg:      cfg,
		keyCache: make(map[string]*rsa.PublicKey),
	}
}

// RequireAuth returns a Gin middleware that rejects requests without a valid
// Cognito access token. On success it sets the Cognito sub in the context.
func (a *Auth) RequireAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := extractBearerToken(ctx.GetHeader("Authorization"))
		if token == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed authorization token"})
			return
		}

		claims, err := a.validateToken(ctx.Request.Context(), token)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		sub, err := claims.GetSubject()
		if err != nil || sub == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token missing subject claim"})
			return
		}

		ctx.Set(string(contextKeyUserSub), sub)
		ctx.Next()
	}
}

// GetUserSub retrieves the Cognito sub injected by RequireAuth.
// Returns ("", false) if called outside an authenticated route.
func GetUserSub(ctx *gin.Context) (string, bool) {
	val, exists := ctx.Get(string(contextKeyUserSub))
	if !exists {
		return "", false
	}
	sub, ok := val.(string)
	return sub, ok
}

// ─────────────────────────────────────────────────────────────────────────────
// Token validation
// ─────────────────────────────────────────────────────────────────────────────

func (a *Auth) validateToken(ctx context.Context, tokenStr string) (jwt.Claims, error) {
	keys, err := a.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	token, err := jwt.Parse(tokenStr,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			kid, _ := token.Header["kid"].(string)
			key, ok := keys[kid]
			if !ok {
				return nil, fmt.Errorf("unknown key ID: %q", kid)
			}
			return key, nil
		},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	return token.Claims, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// JWKS cache
// ─────────────────────────────────────────────────────────────────────────────

const jwksCacheTTL = 1 * time.Hour

func (a *Auth) getKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	a.mu.RLock()
	if len(a.keyCache) > 0 && time.Since(a.fetchedAt) < jwksCacheTTL {
		keys := a.keyCache
		a.mu.RUnlock()
		return keys, nil
	}
	a.mu.RUnlock()

	return a.fetchKeys(ctx)
}

func (a *Auth) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	url := fmt.Sprintf(
		"https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
		a.cfg.AWSRegion,
		a.cfg.CognitoUserPoolID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := decodeRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	a.mu.Lock()
	a.keyCache = keys
	a.fetchedAt = time.Now()
	a.mu.Unlock()

	return keys, nil
}

// decodeRSAPublicKey reconstructs an *rsa.PublicKey from base64url-encoded
// modulus (N) and exponent (E) as provided by a JWK.
func decodeRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func extractBearerToken(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
}
