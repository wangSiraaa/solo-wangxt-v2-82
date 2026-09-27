// Package store 负责 PostgreSQL 持久化:产物摘要、证据(DSSE 信封与声明)与判定结果。
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Record 是一条核验记录。
type Record struct {
	ID             string          `json:"id"`
	CreatedAt      time.Time       `json:"createdAt"`
	Source         string          `json:"source"` // "upload" 或 "demo:<用例名>"
	ArtifactName   string          `json:"artifactName"`
	ArtifactSHA256 string          `json:"artifactSha256"`
	Envelope       json.RawMessage `json:"envelope"`
	Statement      json.RawMessage `json:"statement,omitempty"`
	Result         json.RawMessage `json:"result"` // 完整判定结果(四个面板)
	Decision       string          `json:"decision"`
}

// Summary 是历史列表用的条目。
type Summary struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"createdAt"`
	Source         string    `json:"source"`
	ArtifactName   string    `json:"artifactName"`
	ArtifactSHA256 string    `json:"artifactSha256"`
	Decision       string    `json:"decision"`
}

// Store 包装连接池。
type Store struct {
	pool *pgxpool.Pool
}

const schema = `
CREATE TABLE IF NOT EXISTS verifications (
    id               TEXT PRIMARY KEY,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    source           TEXT NOT NULL,
    artifact_name    TEXT NOT NULL,
    artifact_sha256  TEXT NOT NULL,
    envelope         JSONB NOT NULL,
    statement        JSONB,
    result           JSONB NOT NULL,
    decision         TEXT NOT NULL CHECK (decision IN ('allow','deny'))
);
CREATE INDEX IF NOT EXISTS verifications_created_at_idx ON verifications (created_at DESC);
`

// Connect 建立连接池并自动建库建表。dsn 指向目标库,adminDSN 指向 postgres 库用于建库。
func Connect(ctx context.Context, dsn, adminDSN string) (*Store, error) {
	// 目标库可能不存在,先通过 admin 连接创建
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		return nil, fmt.Errorf("连接 postgres 管理库失败: %w", err)
	}
	defer admin.Close()
	dbName := dbNameFromDSN(dsn)
	if dbName != "" && dbName != "postgres" {
		var exists bool
		if err := admin.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)", dbName).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", pgIdentifier(dbName))); err != nil {
				return nil, fmt.Errorf("创建数据库 %s 失败: %w", dbName, err)
			}
		}
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("初始化表结构失败: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Save 写入一条核验记录,返回记录 ID。
func (s *Store) Save(ctx context.Context, r *Record) (string, error) {
	id := newUUID()
	err := s.pool.QueryRow(ctx, `
		INSERT INTO verifications (id, source, artifact_name, artifact_sha256, envelope, statement, result, decision)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING created_at`,
		id, r.Source, r.ArtifactName, r.ArtifactSHA256, r.Envelope, nullable(r.Statement), r.Result, r.Decision,
	).Scan(&r.CreatedAt)
	if err != nil {
		return "", err
	}
	r.ID = id
	return id, nil
}

// List 返回最近的历史记录。
func (s *Store) List(ctx context.Context, limit int) ([]Summary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, created_at, source, artifact_name, artifact_sha256, decision
		FROM verifications ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		var m Summary
		if err := rows.Scan(&m.ID, &m.CreatedAt, &m.Source, &m.ArtifactName, &m.ArtifactSHA256, &m.Decision); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Get 返回单条完整记录。
func (s *Store) Get(ctx context.Context, id string) (*Record, error) {
	var r Record
	err := s.pool.QueryRow(ctx, `
		SELECT id, created_at, source, artifact_name, artifact_sha256, envelope, statement, result, decision
		FROM verifications WHERE id=$1`, id,
	).Scan(&r.ID, &r.CreatedAt, &r.Source, &r.ArtifactName, &r.ArtifactSHA256, &r.Envelope, &r.Statement, &r.Result, &r.Decision)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func nullable(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}
