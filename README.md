# SpotSpoof CLI

Rust CLI for SpotSpoof.

## Commands
- `spotspoof lookup <domain>` (auto-detect ASCII vs IDN)
- `spotspoof ascii <domain>`
- `spotspoof idn <domain>`
- `spotspoof import --db spotspoof.sqlite --source cleaned_domains.txt --batch-size 100000`
- `spotspoof import --download --url https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof.sqlite.zst`
- `spotspoof serve --host 127.0.0.1 --port 8080 --db spotspoof.sqlite`

## Getting Started
From the repo root:

```bash
cargo run --manifest-path spotspoof-cli/Cargo.toml -- import --db spotspoof.sqlite --source cleaned_domains.txt
cargo run --manifest-path spotspoof-cli/Cargo.toml -- import --download
cargo run --manifest-path spotspoof-cli/Cargo.toml -- lookup gooogle.com
cargo run --manifest-path spotspoof-cli/Cargo.toml -- serve --host 127.0.0.1 --port 8080 --db spotspoof.sqlite
```

## SQLite schema
The importer creates this schema and index:

```sql
CREATE TABLE legit_domains (
  domain TEXT PRIMARY KEY,
  first_char TEXT NOT NULL,
  length INTEGER NOT NULL
);
CREATE INDEX idx_legit_char_len ON legit_domains(first_char, length);
```

## Environment variables
- `WHOIS_TIMEOUT_MS` (default: 2500)
- `WHOIS_MAX_CHECKS` (default: 200)
- `PUNY_MAX_NORMALIZED` (default: 2000)
- `PUNY_MAX_RESULTS` (default: 50)
- `PUNY_MAX_RESULTS_TIMEOUT` (default: 5)

## Notes
- SQLite DB path defaults to `spotspoof.sqlite` next to the binary (falls back to current directory).
- The importer filters domains to match the web app: max length 15, skip first chars `q`, `x`, `z`, `0-9`.
