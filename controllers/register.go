package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/gin-gonic/gin"
)

type RegisterRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Username string `json:"username" binding:"required,min=3"`
	Password string `json:"password" binding:"required,min=8"`
}

type cognitoSignUpRequest struct {
	ClientID       string                 `json:"ClientId"`
	Username       string                 `json:"Username"`
	Password       string                 `json:"Password"`
	SecretHash     string                 `json:"SecretHash,omitempty"`
	UserAttributes []cognitoAttributePair `json:"UserAttributes"`
}

type cognitoSignUpResponse struct {
	UserSub      string `json:"UserSub"`
	UserConfirmed bool   `json:"UserConfirmed"`
}

// Register creates a new Cognito user, auto-confirms them, marks the email as
// verified, and inserts a corresponding record into the users table.
func (h *Handler) Register(ctx *gin.Context) {
	var req RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)

	// ── 1. SignUp via direct HTTP (avoids SDK overhead for this simple call) ──
	payload := cognitoSignUpRequest{
		ClientID:   h.cfg.CognitoClientID,
		Username:   username,
		Password:   req.Password,
		SecretHash: h.computeSecretHash(username),
		UserAttributes: []cognitoAttributePair{
			{Name: "email", Value: email},
			{Name: "preferred_username", Value: username},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build Cognito request"})
		return
	}

	httpReq, err := http.NewRequestWithContext(ctx.Request.Context(), http.MethodPost,
		h.cognitoEndpoint(), bytes.NewReader(bodyBytes))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create Cognito request"})
		return
	}
	httpReq.Header.Set("Content-Type", "application/x-amz-json-1.1")
	httpReq.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.SignUp")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": "failed to reach Cognito"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var cognitoErr cognitoErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&cognitoErr)
		ctx.JSON(mapRegisterStatusCode(cognitoErr.Type), gin.H{"error": cognitoMessage(cognitoErr)})
		return
	}

	var signUpResp cognitoSignUpResponse
	if err := json.NewDecoder(resp.Body).Decode(&signUpResp); err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": "failed to decode Cognito signup response"})
		return
	}

	// ── 2. Auto-confirm + verify email via Admin API ──────────────────────────
	awsCfg, err := config.LoadDefaultConfig(ctx.Request.Context(), config.WithRegion(h.cfg.AWSRegion))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load AWS config"})
		return
	}

	cognitoClient := cognitoidentityprovider.NewFromConfig(awsCfg)

	if _, err = cognitoClient.AdminConfirmSignUp(ctx.Request.Context(),
		&cognitoidentityprovider.AdminConfirmSignUpInput{
			UserPoolId: strPtr(h.cfg.CognitoUserPoolID),
			Username:   strPtr(username),
		}); err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": "admin confirm failed: " + awsErrorMessage(err)})
		return
	}

	if _, err = cognitoClient.AdminUpdateUserAttributes(ctx.Request.Context(),
		&cognitoidentityprovider.AdminUpdateUserAttributesInput{
			UserPoolId: strPtr(h.cfg.CognitoUserPoolID),
			Username:   strPtr(username),
			UserAttributes: []types.AttributeType{
				{Name: strPtr("email_verified"), Value: strPtr("true")},
			},
		}); err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": "email verify update failed: " + awsErrorMessage(err)})
		return
	}

	// ── 3. Persist user in our database ──────────────────────────────────────
	_, err = h.db.Exec(ctx.Request.Context(),
		`INSERT INTO users (cognito_sub, email, username)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (cognito_sub) DO NOTHING`,
		signUpResp.UserSub, email, username,
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user record"})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "Registration successful"})
}
