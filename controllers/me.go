package controllers

import (
	"context"
	"net/http"

	"github.com/InspectorGadget/lolopien/middleware"
	"github.com/InspectorGadget/lolopien/models"
	"github.com/gin-gonic/gin"
)

// Me returns the authenticated user's profile.
// Requires the RequireAuth middleware to be applied on the route group.
func (h *Handler) Me(ctx *gin.Context) {
	sub, ok := middleware.GetUserSub(ctx)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	user, err := h.getUserBySub(ctx.Request.Context(), sub)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"id":         user.ID,
		"email":      user.Email,
		"username":   user.Username,
		"created_at": user.CreatedAt,
	})
}

// getUserBySub fetches a user record by their Cognito sub (JWT subject claim).
func (h *Handler) getUserBySub(ctx context.Context, sub string) (*models.User, error) {
	user := &models.User{}
	err := h.db.QueryRow(ctx,
		`SELECT id::text, cognito_sub, email, username, is_active, created_at, updated_at
		 FROM users
		 WHERE cognito_sub = $1 AND is_active = TRUE`,
		sub,
	).Scan(
		&user.ID,
		&user.CognitoSub,
		&user.Email,
		&user.Username,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}
