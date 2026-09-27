// Package store persists verification records. PostgreSQL is the primary
// backend; an in-memory backend is provided so the workbench still runs
// (and demos/tests work) when no database is configured.
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/verifybench/internal/verify"
)

// ErrNotFound is returned when a record id does not exist.
var ErrNotFound = errors.New("verification record not found")

// ErrArtifactUnavailable indicates bytes were never retained (denied records
// never store artifact content).
var ErrArtifactUnavailable = errors.New("artifact bytes unavailable")

// Store is the persistence contract.
type Store interface {
	Save(ctx context.Context, rec *verify.Record) error
	Get(ctx context.Context, id string) (*verify.Record, error)
	List(ctx context.Context, limit, offset int) ([]*verify.Record, int, error)
	// SaveArtifact retains artifact bytes. It must only be called for records
	// whose policy decision was Allow; denied content is never persisted.
	SaveArtifact(ctx context.Context, id string, content []byte) error
	LoadArtifact(ctx context.Context, id string) ([]byte, error)
	Kind() string
	Close()
}

// assignID fills ID/CreatedAt if empty.
func assignID(rec *verify.Record) {
	if rec.ID == "" {
		rec.ID = uuid.NewString()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
}

// ---------------------------------------------------------------------------
// PostgreSQL backend
// ---------------------------------------------------------------------------

const schema = `
CREATE TABLE IF NOT EXISTS verifications (
    id              UUID PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    artifact_name   TEXT NOT NULL,
    artifact_size   BIGINT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    payload_type    TEXT NOT NULL DEFAULT '',
    builder_id      TEXT NOT NULL DEFAULT '',
    build_type      TEXT NOT NULL DEFAULT '',
    source_uri      TEXT NOT NULL DEFAULT '',
    source_commit   TEXT NOT NULL DEFAULT '',
    subject_digest  TEXT NOT NULL DEFAULT '',
    allow           BOOLEAN NOT NULL DEFAULT FALSE,
    envelope_raw    TEXT NOT NULL,
    statement       JSONB,
    signatures      JSONB NOT NULL DEFAULT '[]',
    checks          JSONB NOT NULL DEFAULT '{}',
    violations      JSONB NOT NULL DEFAULT '[]',
    fatal           JSONB
);
CREATE TABLE IF NOT EXISTS verification_artifacts (
    verification_id UUID PRIMARY KEY REFERENCES verifications(id) ON DELETE CASCADE,
    content         BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS verifications_created_at_idx ON verifications (created_at DESC);
CREATE INDEX IF NOT EXISTS verifications_artifact_idx   ON verifications (artifact_sha256);
`

// PG is the PostgreSQL-backed store.
type PG struct {
	pool *pgxpool.Pool
}

// NewPG connects to PostgreSQL and ensures the schema exists.
func NewPG(ctx context.Context, connString string) (*PG, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure schema: %w", err)
	}
	return &PG{pool: pool}, nil
}

// SaveArtifact stores artifact bytes for an ALLOWED record.
func (p *PG) SaveArtifact(ctx context.Context, id string, content []byte) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO verification_artifacts (verification_id, content) VALUES ($1, $2)
		 ON CONFLICT (verification_id) DO UPDATE SET content = EXCLUDED.content`,
		id, content)
	return err
}

// LoadArtifact reads retained artifact bytes.
func (p *PG) LoadArtifact(ctx context.Context, id string) ([]byte, error) {
	var content []byte
	err := p.pool.QueryRow(ctx,
		`SELECT content FROM verification_artifacts WHERE verification_id = $1`, id).Scan(&content)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrArtifactUnavailable
		}
		return nil, err
	}
	return content, nil
}

// Kind reports the backend type.
func (p *PG) Kind() string { return "postgres" }

// Close releases the pool.
func (p *PG) Close() { p.pool.Close() }

// Save inserts a verification record.
func (p *PG) Save(ctx context.Context, rec *verify.Record) error {
	assignID(rec)
	_, err := p.pool.Exec(ctx, `
		INSERT INTO verifications
		  (id, created_at, artifact_name, artifact_size, artifact_sha256, payload_type,
		   builder_id, build_type, source_uri, source_commit, subject_digest, allow,
		   envelope_raw, statement, signatures, checks, violations, fatal)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		rec.ID, rec.CreatedAt, rec.ArtifactName, rec.ArtifactSize, rec.ArtifactSHA256,
		rec.PayloadType, rec.BuilderID, rec.BuildType, rec.SourceURI, rec.SourceCommit,
		rec.SubjectDigest, rec.Allow,
		[]byte(rec.EnvelopeRaw), jsonbOrNull(rec.Statement), jsonb(mustJSON(rec.Signatures)),
		jsonb(mustJSON(rec.Checks)), jsonb(mustJSON(rec.Violations)), jsonbOrNull(mustJSON(rec.Fatal)),
	)
	return err
}

// Get fetches one record by id.
func (p *PG) Get(ctx context.Context, id string) (*verify.Record, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, created_at, artifact_name, artifact_size, artifact_sha256, payload_type,
		       builder_id, build_type, source_uri, source_commit, subject_digest, allow,
		       envelope_raw, statement, signatures, checks, violations, fatal
		FROM verifications WHERE id = $1`, id)
	return scanRecord(row)
}

// List returns records newest-first plus the total count.
func (p *PG) List(ctx context.Context, limit, offset int) ([]*verify.Record, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM verifications`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, created_at, artifact_name, artifact_size, artifact_sha256, payload_type,
		       builder_id, build_type, source_uri, source_commit, subject_digest, allow,
		       envelope_raw, statement, signatures, checks, violations, fatal
		FROM verifications ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*verify.Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rec)
	}
	return out, total, rows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanRecord(row rowScanner) (*verify.Record, error) {
	var rec verify.Record
	var stmt, fatal []byte
	err := row.Scan(
		&rec.ID, &rec.CreatedAt, &rec.ArtifactName, &rec.ArtifactSize, &rec.ArtifactSHA256,
		&rec.PayloadType, &rec.BuilderID, &rec.BuildType, &rec.SourceURI, &rec.SourceCommit,
		&rec.SubjectDigest, &rec.Allow,
		&rec.EnvelopeRaw, &stmt, &rec.Signatures, &rec.Checks, &rec.Violations, &fatal,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if stmt != nil {
		rec.Statement = stmt
	}
	if fatal != nil {
		_ = jsonUnmarshal(fatal, &rec.Fatal)
	}
	return &rec, nil
}

// ---------------------------------------------------------------------------
// In-memory backend (fallback when PostgreSQL is not configured)
// ---------------------------------------------------------------------------

// Mem is a process-local store.
type Mem struct {
	mu        sync.RWMutex
	records   []*verify.Record
	byID      map[string]*verify.Record
	artifacts map[string][]byte
}

// NewMem creates an empty in-memory store.
func NewMem() *Mem {
	return &Mem{byID: map[string]*verify.Record{}, artifacts: map[string][]byte{}}
}

// Kind reports the backend type.
func (m *Mem) Kind() string { return "memory" }

// Close is a no-op.
func (m *Mem) Close() {}

// Save appends a record.
func (m *Mem) Save(_ context.Context, rec *verify.Record) error {
	assignID(rec)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	m.byID[rec.ID] = rec
	return nil
}

// Get fetches a record by id.
func (m *Mem) Get(_ context.Context, id string) (*verify.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return rec, nil
}

// SaveArtifact retains artifact bytes for an ALLOWED record.
func (m *Mem) SaveArtifact(_ context.Context, id string, content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(content))
	copy(cp, content)
	m.artifacts[id] = cp
	return nil
}

// LoadArtifact reads retained artifact bytes.
func (m *Mem) LoadArtifact(_ context.Context, id string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.artifacts[id]
	if !ok {
		return nil, ErrArtifactUnavailable
	}
	return data, nil
}

// List returns records newest-first.
func (m *Mem) List(_ context.Context, limit, offset int) ([]*verify.Record, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	sorted := make([]*verify.Record, len(m.records))
	copy(sorted, m.records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CreatedAt.After(sorted[j].CreatedAt) })
	total := len(sorted)
	if offset > total {
		return nil, total, nil
	}
	sorted = sorted[offset:]
	if len(sorted) > limit {
		sorted = sorted[:limit]
	}
	return sorted, total, nil
}
