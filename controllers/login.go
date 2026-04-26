package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type cognitoLoginRequest struct {
	AuthFlow       string            `json:"AuthFlow"`
	ClientID       string            `json:"ClientId"`
	AuthParameters map[string]string `json:"AuthParameters"`
}

type cognitoAuthResult struct {
	AccessToken  string `json:"AccessToken"`
	IDToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	ExpiresIn    int    `json:"ExpiresIn"`
}

type cognitoLoginResponse struct {
	AuthenticationResult cognitoAuthResult `json:"AuthenticationResult"`
	ChallengeName        string            `json:"ChallengeName"`
}

// Login authenticates a user via Cognito USER_PASSWORD_AUTH and returns the
// three JWT tokens (access, id, refresh) on success.
func (h *Handler) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := strings.TrimSpace(req.Username)

	authParams := map[string]string{
		"USERNAME": username,
		"PASSWORD": req.Password,
	}
	if secretHash := h.computeSecretHash(username); secretHash != "" {
		authParams["SECRET_HASH"] = secretHash
	}

	payload := cognitoLoginRequest{
		AuthFlow:       "USER_PASSWORD_AUTH",
		ClientID:       h.cfg.CognitoClientID,
		AuthParameters: authParams,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build Cognito login request"})
		return
	}

	httpReq, err := http.NewRequestWithContext(ctx.Request.Context(), http.MethodPost,
		h.cognitoEndpoint(), bytes.NewReader(bodyBytes))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create Cognito login request"})
		return
	}
	httpReq.Header.Set("Content-Type", "application/x-amz-json-1.1")
	httpReq.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.InitiateAuth")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": "failed to reach Cognito"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var cognitoErr cognitoErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&cognitoErr)
		ctx.JSON(mapLoginStatusCode(cognitoErr.Type), gin.H{"error": cognitoMessage(cognitoErr)})
		return
	}

	var cognitoResp cognitoLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&cognitoResp); err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": "failed to decode Cognito login response"})
		return
	}

	if strings.TrimSpace(cognitoResp.ChallengeName) != "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error":     "additional challenge required",
			"challenge": cognitoResp.ChallengeName,
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token":  cognitoResp.AuthenticationResult.AccessToken,
		"id_token":      cognitoResp.AuthenticationResult.IDToken,
		"refresh_token": cognitoResp.AuthenticationResult.RefreshToken,
		"token_type":    cognitoResp.AuthenticationResult.TokenType,
		"expires_in":    cognitoResp.AuthenticationResult.ExpiresIn,
	})
}
