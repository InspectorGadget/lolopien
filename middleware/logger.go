package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger returns a Gin middleware that emits a structured slog entry after
// each request, including method, path, status code, latency, and client IP.
func Logger(logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		path := ctx.Request.URL.Path
		if ctx.Request.URL.RawQuery != "" {
			path += "?" + ctx.Request.URL.RawQuery
		}

		ctx.Next()

		logger.Info("request",
			"method",      ctx.Request.Method,
			"path",        path,
			"status",      ctx.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"ip",          ctx.ClientIP(),
			"user_agent",  ctx.Request.UserAgent(),
		)
	}
}
