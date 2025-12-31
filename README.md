# SpotSpoof CLI

SpotSpoof is a FOSS Rust CLI for phishing and domain spoof analysis. It detects ASCII and IDN (punycode) spoof candidates and is designed for security teams to run in automation pipelines or SOAR workflows.

## Use Cases
- Triage suspicious domains from email, DNS, or proxy logs.
- Enrich alerts with spoof candidates and IDN lookups.
- Run a local HTTP service for high-volume automation.

## Install
### Download a Release Binary (Recommended)
Releases include a macOS binary and a compressed SQLite database (`spotspoof.sqlite.zst`). Download the binary and database from GitHub Releases, then:

```bash
./spotspoof import --download
./spotspoof lookup gooogle.com
```

### Build from Source
```bash
cargo build --release
./target/release/spotspoof-cli import --download
./target/release/spotspoof-cli lookup gooogle.com
```

## Commands
- `spotspoof lookup <domain>` (auto-detect ASCII vs IDN)
- `spotspoof ascii <domain>`
- `spotspoof idn <domain>`
- `spotspoof import --db spotspoof.sqlite --source cleaned_domains.txt --batch-size 100000`
- `spotspoof import --download --url https://github.com/slimpagey/spotspoof-cli/releases/latest/spotspoof.sqlite.zst`
- `spotspoof serve --host 127.0.0.1 --port 8080 --db spotspoof.sqlite`

## Automation & SOAR Integration
- Use JSON (default), `--text`, or `--csv` depending on your pipeline:
  - `spotspoof lookup gooogle.com`
  - `spotspoof ascii --text gooble.com`
  - `spotspoof idn --csv амаzоn.com`
- Run the HTTP server and call it from your orchestration tooling:
  - `spotspoof serve --host 127.0.0.1 --port 8080 --db spotspoof.sqlite`
- Logging can be customized with:
  - `--log-format plain|json`
  - `--log-destination stdout|stderr|file --log-file /path/to/spotspoof.log`

## API Server Routes
- `GET /` basic landing page listing routes
- `GET /healthz` health check (`{"ok":true}`)
- `POST /lookup` auto-detect ASCII vs IDN
- `POST /ascii` ASCII spoof lookup
- `POST /idn` IDN spoof lookup
- `GET /docs` Swagger UI (OpenAPI)

Request body format:

```json
{ "domain": "gooble.com" }
```

## Logging
SpotSpoof uses structured logging via `tracing`. Configure output and destination with:

```bash
spotspoof --log-format json --log-destination stdout lookup gooogle.com
spotspoof --log-destination file --log-file /var/log/spotspoof.log lookup gooogle.com
```

## Output Formats
- JSON (default): pretty-printed structured output.
- Text: ASCII output in `Domain: <domain>, Similarity: <score>` format; IDN output in `Domain: <domain>, Mappings: <ascii> -> <unicode>` format.
- CSV: ASCII output as `domain,similarity`; IDN output as `domain,mappings` with mappings joined by `|` (e.g., `a->а|m->м`).
- Use `-o/--outfile` to write output to a file, e.g. `spotspoof idn --csv амаzоn.com -o result.csv`.

## DB Integrity
`import --download` verifies the compressed database SHA-256 before decompressing. Update `config/db_sha256.txt` (or set `SPOTSPOOF_DB_SHA256_PATH`) when the release DB changes.

## Pull Requests
We welcome contributions. Please use the PR template and include a short summary, test results (or why tests weren’t run), and any relevant screenshots/log samples.

## Getting Started (Repo Root)
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
