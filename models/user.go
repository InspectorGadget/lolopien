package models

import "time"

// User is the internal user record, linked to a Cognito identity via CognitoSub.
type User struct {
	ID         string    `db:"id"`
	CognitoSub string    `db:"cognito_sub"`
	Email      string    `db:"email"`
	Username   string    `db:"username"`
	IsActive   bool      `db:"is_active"`
	CreatedAt  time.Time `db:"created_at"`
	UpdatedAt  time.Time `db:"updated_at"`
}
