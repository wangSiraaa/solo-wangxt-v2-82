// Command server runs the supply-chain verification workbench API and serves
// the built frontend.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/example/verifybench/internal/api"
	"github.com/example/verifybench/internal/demo"
	"github.com/example/verifybench/internal/policy"
	"github.com/example/verifybench/internal/store"
	"github.com/example/verifybench/internal/trust"
	"github.com/example/verifybench/internal/verify"
)

func main() {
	addr := envOr("ADDR", ":8080")
	trustPath := envOr("TRUST_ROOT", "")
	databaseURL := envOr("DATABASE_URL", "")
	frontendDist := envOr("FRONTEND_DIST", "../frontend/dist")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Trust root: explicit file, else the embedded demo trust root.
	var root *trust.Root
	var err error
	if trustPath != "" {
		root, err = trust.LoadFile(trustPath)
	} else {
		root, err = trust.Load(demo.TrustRoot())
		log.Printf("no TRUST_ROOT configured, using embedded demo trust root")
	}
	if err != nil {
		log.Fatalf("load trust root: %v", err)
	}
	log.Printf("trust root: %d trusted keys, allowed hosts %v, allowed build types %v",
		len(root.Ring), root.Config.AllowedSourceHosts, root.Config.AllowedBuildTypes)

	eval, err := policy.New()
	if err != nil {
		log.Fatalf("compile policy: %v", err)
	}

	// Store: PostgreSQL when DATABASE_URL is set, otherwise in-memory so the
	// workbench remains runnable for demos/tests.
	var st store.Store
	if databaseURL != "" {
		st, err = store.NewPG(ctx, databaseURL)
		if err != nil {
			log.Fatalf("connect postgres: %v", err)
		}
		log.Printf("store: postgres")
	} else {
		st = store.NewMem()
		log.Printf("store: in-memory (set DATABASE_URL to use PostgreSQL)")
	}
	defer st.Close()

	srv := api.NewServer(verify.New(root, eval), st, root)

	rootHandler := withFrontend(srv.Handler(), frontendDist)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           rootHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("verifybench listening on %s", addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http server: %v", err)
	}
}

// withFrontend serves the built SPA for non-/api paths when the dist
// directory exists; unknown non-file paths fall back to index.html.
func withFrontend(apiHandler http.Handler, dist string) http.Handler {
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		return apiHandler
	}
	fileServer := http.FileServer(http.Dir(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		path := filepath.Join(dist, filepath.Clean("/"+r.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(dist, "index.html"))
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
