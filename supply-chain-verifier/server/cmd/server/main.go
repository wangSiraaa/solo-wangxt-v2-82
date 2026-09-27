// 供应链核验工作台服务端。
//
// 职责:解析 DSSE 信封与 in-toto 声明、Ed25519 验签、SHA-256 摘要比对、
// OPA 信任策略求值、PostgreSQL 持久化,并提供 HTTP API。
// 上传的产物只参与摘要计算,任何失败路径都不会执行产物内容。
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/example/supply-chain-verifier/internal/api"
	"github.com/example/supply-chain-verifier/internal/store"
	"github.com/example/supply-chain-verifier/internal/verify"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	root := env("APP_ROOT", ".")
	dsn := env("DATABASE_URL", "postgres://postgres@localhost:5432/supplychain?sslmode=disable")
	adminDSN := env("ADMIN_DATABASE_URL", "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	addr := env("ADDR", ":8080")

	// 加载已知公钥密钥环
	keyringBytes, err := os.ReadFile(filepath.Join(root, "fixtures", "keys", "keyring.json"))
	if err != nil {
		log.Fatalf("读取密钥环失败: %v(请先运行 go run ./cmd/genfixtures)", err)
	}
	var keys []verify.Key
	if err := json.Unmarshal(keyringBytes, &keys); err != nil {
		log.Fatalf("解析密钥环失败: %v", err)
	}

	// 加载 OPA 信任策略
	eval, err := verify.NewPolicyEvaluator(ctx,
		filepath.Join(root, "policy", "trust.rego"),
		filepath.Join(root, "policy", "trusted.json"))
	if err != nil {
		log.Fatalf("加载 OPA 策略失败: %v", err)
	}

	verifier, err := verify.New(keys, eval)
	if err != nil {
		log.Fatalf("初始化核验器失败: %v", err)
	}

	// 连接 PostgreSQL(自动建库建表),等待数据库就绪
	var st *store.Store
	for i := 0; i < 30; i++ {
		st, err = store.Connect(ctx, dsn, adminDSN)
		if err == nil {
			break
		}
		log.Printf("等待数据库就绪: %v", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	srv := api.New(verifier, st, filepath.Join(root, "fixtures"))

	// 若前端已构建,则由同一端口托管静态文件
	mux := srv.Handler()
	if dist := filepath.Join(root, "web", "dist"); dirExists(dist) {
		fs := http.FileServer(http.Dir(dist))
		mux = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
				srv.Handler().ServeHTTP(w, r)
				return
			}
			fs.ServeHTTP(w, r)
		})
	}

	log.Printf("供应链核验工作台监听于 %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
