package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/InspectorGadget/lolopien/config"
	"github.com/InspectorGadget/lolopien/controllers"
	"github.com/InspectorGadget/lolopien/db"
	"github.com/InspectorGadget/lolopien/middleware"
	"github.com/InspectorGadget/lolopien/services/encrypt"
	"github.com/InspectorGadget/lolopien/services/peersync"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// ── Load .env (dev only — silently ignored if file doesn't exist) ────────
	_ = godotenv.Load()

	// ── Structured logging ───────────────────────────────────────────────────
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// ── Config ───────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// ── AWS SDK config (shared across all AWS services) ──────────────────────
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		slog.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	// ── Database ─────────────────────────────────────────────────────────────
	pool, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.RunMigrations(ctx, pool); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("database ready")

	// ── Services ─────────────────────────────────────────────────────────────
	encSvc := encrypt.New(awsCfg, cfg.KMSKeyARN)
	syncSvc := peersync.New(awsCfg, pool)

	// ── Handler + Router ─────────────────────────────────────────────────────
	h := controllers.NewHandler(cfg, pool, encSvc, syncSvc)
	auth := middleware.NewAuth(cfg)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Logger(logger))

	// Public routes
	r.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	r.POST("/register", h.Register)
	r.POST("/login", h.Login)

	// Authenticated routes
	v1 := r.Group("/v1")
	v1.Use(auth.RequireAuth())
	{
		v1.GET("/me", h.Me)

		// Device management
		v1.POST("/devices", h.RegisterDevice)
		v1.GET("/devices", h.ListDevices)
		v1.DELETE("/devices/:id", h.RevokeDevice)

		// Config download
		v1.GET("/vpn/config/:device_id", h.GetConfig)
	}

	// ── HTTP server with graceful shutdown ───────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server starting", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("forced shutdown", "error", err)
	} else {
		slog.Info("server stopped cleanly")
	}
}
