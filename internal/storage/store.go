// Package storage persists LANChat state in SQLite (pure-Go driver, no CGO).
//
// The database runs in WAL mode with foreign keys enabled and a busy
// timeout. All statements are parameterised. Schema changes are applied by
// numbered, embedded migrations; before an existing database is migrated a
// backup copy is written next to it so user data is never silently lost.
package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrCorrupt indicates the database file is unreadable.
var ErrCorrupt = errors.New("database is corrupted or not a LANChat database")

// Store is a handle to the LANChat database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if necessary) the database at path and applies any
// pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		// Create the file with owner-only permissions before SQLite does;
		// SQLite gives the -wal and -shm files the same permissions.
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open database file: %w", err)
		}
		_ = f.Close()
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)&_txlock=immediate"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1) // each connection would otherwise get its own empty database
	} else {
		db.SetMaxOpenConns(4)
	}
	s := &Store{db: db, path: path}
	if err := s.ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) ping(ctx context.Context) error {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&n)
	if err != nil {
		if strings.Contains(err.Error(), "not a database") || strings.Contains(err.Error(), "malformed") {
			return fmt.Errorf("%w (%s): %v", ErrCorrupt, s.path, err)
		}
		return fmt.Errorf("open database %s: %w", s.path, err)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("migration %s has no version prefix", name)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %s has an invalid version", name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := range out {
		if out[i].version != i+1 {
			return nil, fmt.Errorf("migrations are not contiguous at %s", out[i].name)
		}
	}
	return out, nil
}

// LatestSchemaVersion returns the schema version this build migrates to.
func LatestSchemaVersion() int {
	m, err := loadMigrations()
	if err != nil || len(m) == 0 {
		return 0
	}
	return m[len(m)-1].version
}

// SchemaVersion returns the version currently applied to the database.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT max(version) FROM schema_migrations").Scan(&v)
	if err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("initialise migrations: %w", err)
	}
	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	latest := 0
	if len(migs) > 0 {
		latest = migs[len(migs)-1].version
	}
	if current > latest {
		return fmt.Errorf("database schema version %d is newer than this LANChat build supports (%d); upgrade LANChat", current, latest)
	}
	if current == latest {
		return nil
	}
	if current > 0 && s.path != ":memory:" {
		backup := fmt.Sprintf("%s.bak-v%d-%s", s.path, current, time.Now().UTC().Format("20060102T150405Z"))
		if err := s.Backup(ctx, backup); err != nil {
			return fmt.Errorf("back up database before migration: %w", err)
		}
	}
	for _, m := range migs {
		if m.version <= current {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
			m.version, m.name, time.Now().UnixMilli()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.name, err)
		}
	}
	return nil
}

// Backup writes a consistent copy of the database to dest using
// VACUUM INTO. dest must not exist.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("backup destination %s already exists", dest)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("backup to %s: %w", dest, err)
	}
	_ = os.Chmod(dest, 0o600)
	return nil
}

// QuickCheck runs SQLite's quick_check integrity verification.
func (s *Store) QuickCheck(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return err
		}
		if r != "ok" {
			problems = append(problems, r)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrCorrupt, strings.Join(problems, "; "))
	}
	return nil
}

// Stats summarises database contents for diagnostics.
type Stats struct {
	Peers, TrustedPeers, Conversations, Messages, PendingDeliveries int
}

// Stats returns row counts.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM peers),
		(SELECT count(*) FROM peers WHERE trust = 'trusted'),
		(SELECT count(*) FROM conversations),
		(SELECT count(*) FROM messages),
		(SELECT count(*) FROM deliveries WHERE status IN ('pending', 'sent'))`).
		Scan(&st.Peers, &st.TrustedPeers, &st.Conversations, &st.Messages, &st.PendingDeliveries)
	return st, err
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
