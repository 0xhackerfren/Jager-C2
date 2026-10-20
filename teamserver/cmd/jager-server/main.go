package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xhackerfren/Jager-C2/teamserver/internal/server"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	var (
		grpcAddr    = flag.String("grpc", "127.0.0.1:31337", "gRPC listen address")
		mgmtAddr    = flag.String("mgmt", "127.0.0.1:31338", "Management REST API address")
		dbPath      = flag.String("db", "jager.db", "SQLite database path")
		workspace   = flag.String("workspace", "", "Workspace root (defaults to the repo root; contains builder/, profiles/, data/)")
		builderPath = flag.String("builder", "", "Path to build_implant.py (default: <workspace>/builder/build_implant.py)")
		certFile    = flag.String("cert", "certs/server.pem", "TLS certificate")
		keyFile     = flag.String("key", "certs/server-key.pem", "TLS private key")
		caFile      = flag.String("ca", "certs/ca.pem", "CA certificate for mTLS")
		noTLS       = flag.Bool("no-tls", false, "Disable mTLS (dev mode only)")
		mgmtTLS     = flag.Bool("mgmt-tls", false, "Enable TLS for management REST API")
		logLevel    = flag.String("log-level", "info", "Log level: debug, info, warn, error")
	)
	flag.Parse()

	ws := *workspace
	if ws == "" {
		ws = os.Getenv("HARNESS_WORKSPACE")
	}
	if ws == "" {
		ws = os.Getenv("JAGER_WORKSPACE")
	}

	if ws != "" {
		os.Setenv("JAGER_WORKSPACE", ws)
	}

	logger := initLogger(*logLevel)
	defer logger.Sync()

	keyStore := server.NewAPIKeyStore(logger.Named("apikey"))
	apiKey := keyStore.LoadDefault(ws, *dbPath)

	logger.Info("Jager-C2 Teamserver starting",
		zap.String("grpc_addr", *grpcAddr),
		zap.String("db_path", *dbPath),
	)

	cfg := &server.Config{
		GRPCAddr:    *grpcAddr,
		DBPath:      *dbPath,
		Workspace:   ws,
		BuilderPath: *builderPath,
		CertFile:    *certFile,
		KeyFile:     *keyFile,
		CAFile:      *caFile,
		NoTLS:       *noTLS,
	}

	srv, err := server.New(cfg, logger, keyStore)
	if err != nil {
		logger.Fatal("failed to create server", zap.Error(err))
	}
	_ = apiKey

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Start(ctx)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Fatal("failed to listen", zap.Error(err))
	}

	var grpcServer *grpc.Server
	if cfg.NoTLS {
		logger.Warn("TLS DISABLED - development mode only; gRPC requires API key auth")
		grpcServer = grpc.NewServer(grpc.UnaryInterceptor(server.RBACInterceptor(keyStore, srv.AuthManager())))
	} else {
		tlsCreds, err := loadTLSCredentials(cfg)
		if err != nil {
			logger.Fatal("failed to load TLS credentials", zap.Error(err))
		}
		grpcServer = grpc.NewServer(
			grpc.Creds(tlsCreds),
			grpc.UnaryInterceptor(server.RBACInterceptor(keyStore, srv.AuthManager())),
		)
	}

	srv.Register(grpcServer)

	go func() {
		logger.Info("gRPC server listening", zap.String("addr", cfg.GRPCAddr))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("gRPC serve failed", zap.Error(err))
		}
	}()

	// Start the REST management API (for MCP server communication)
	if err := srv.StartManagementAPI(*mgmtAddr, *mgmtTLS); err != nil {
		logger.Fatal("failed to start management API", zap.Error(err))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down gracefully...")
	cancel()
	grpcServer.GracefulStop()
	srv.Shutdown()
	logger.Info("Jager-C2 Teamserver stopped")
}

func loadTLSCredentials(cfg *server.Config) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("parse CA certificate")
		}
		tlsConfig.ClientCAs = pool
	}

	return credentials.NewTLS(tlsConfig), nil
}

func initLogger(level string) *zap.Logger {
	var cfg zap.Config
	switch level {
	case "debug":
		cfg = zap.NewDevelopmentConfig()
	default:
		cfg = zap.NewProductionConfig()
	}
	logger, _ := cfg.Build()
	return logger
}
