SHELL := /bin/bash
export PATH := $(HOME)/tools/go/bin:$(PATH)
export GOPATH := $(HOME)/gopath

APP_ROOT := $(CURDIR)
export APP_ROOT
export DATABASE_URL ?= postgres://postgres@localhost:5432/supplychain?sslmode=disable
export ADMIN_DATABASE_URL ?= postgres://postgres@localhost:5432/postgres?sslmode=disable

.PHONY: fixtures build-server build-web run dev-web test clean

## 生成三组固定演示数据(密钥、产物、DSSE 信封)
fixtures:
	cd server && go run ./cmd/genfixtures ../fixtures

## 编译后端
build-server:
	cd server && go build ./...

## 构建前端静态文件(构建后由 Go 服务在 :8080 托管)
build-web:
	cd web && npm install && npm run build

## 启动后端(需 PostgreSQL 已运行,自动建库建表)
run: fixtures
	cd server && go run ./cmd/server

## 前端开发服务器(代理 /api 到 :8080)
dev-web:
	cd web && npm run dev

## 运行三组演示用例并打印判定
demo-check:
	@for c in valid tampered untrusted-builder; do \
		printf "%-18s -> " $$c; \
		curl -s -X POST localhost:8080/api/demos/$$c/verify | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['decision'])"; \
	done

clean:
	rm -rf web/dist web/node_modules
