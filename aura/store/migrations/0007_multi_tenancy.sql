-- Migration 0007: In-App Multi-Tenancy Support
ALTER TABLE trades ADD COLUMN account_id TEXT NOT NULL DEFAULT 'master';
CREATE INDEX IF NOT EXISTS idx_trades_account ON trades (account_id, status);

CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    starting_equity REAL NOT NULL DEFAULT 10000.0,
    created_at_ms INTEGER NOT NULL
);

INSERT OR IGNORE INTO accounts (id, name, starting_equity, created_at_ms)
VALUES ('master', 'Ivo (Master)', 10000.0, 1726000000000),
       ('buddy', 'Kumpel (Buddy)', 10000.0, 1726000000000);
