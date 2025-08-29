# CVEDB — A Minimal CVE Database (PostgreSQL + Python CLI)

## 1) Overview
**Goal:** Build a useful, usable CVE-like database that stores vulnerabilities and supports basic analyst workflows (search, status tracking, exports).

**Stack:**
- **Database:** PostgreSQL (via Docker Compose)
- **Access:** SQLAlchemy (Python)
- **Interface:** Python CLI (Click)
- **Artifacts:** `schema.sql` (schema-only dump), CSV export samples in `samples/`

**What this solves:** A compact way to track vulnerabilities, link them to vendors/products, filter by severity/date, and export results for analysis/reporting.

---

## 2) How to Run

### Prereqs
- Docker Desktop installed and running
- Python 3.11+ with `venv`

### Setup
```bash
# clone & enter
git clone <your repo url>
cd cvedb-pg

# start Postgres + Adminer
docker compose up -d

# create virtualenv + deps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# env (on host)
cp .env.example .env
# .env should contain:
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=cvedb
# DB_USER=postgres
# DB_PASSWORD=postgres
```

### Optional: Ingest from NVD (live data)

This project can fetch a single CVE from NVD (v2.0) and upsert it into the database.

```bash
# Example: Log4Shell
python -m app.cli ingest-cve CVE-2021-44228

# Verify from CLI
python -m app.cli search --keyword log4j

# Idempotency: re-running will not duplicate references
python -m app.cli ingest-cve CVE-2021-44228


### Track A — Console (CLI-first, reproductibil)

#### Initialize & seed
```bash
python -m app.cli init
python -m app.cli insert-sample

#### Search & export
```bash
# Query CVEs containing "XSS" with severity HIGH
python -m app.cli search --keyword XSS --severity HIGH

# Ensure the samples folder exists (safe to run multiple times)
mkdir -p samples

# Export the same filter to a CSV artifact
python -m app.cli export-csv --severity HIGH --outfile samples/high.csv

# (optional) Inspect the first lines of the CSV
head -n 5 samples/high.csv

#### Schema dump (DDL)
```bash
# Dump only the database schema (no rows) into schema.sql
docker compose exec -T db pg_dump -U postgres -d cvedb --schema-only > schema.sql

# (optional) Quick sanity checks
ls -lh schema.sql
head -n 20 schema.sql


### Track B — Adminer (visual)

1) Open **http://localhost:8080**
2) Login:
   - **System:** PostgreSQL
   - **Server:** `db`
   - **Username:** `postgres`
   - **Password:** `postgres`
   - **Database:** `cvedb`

3) Inspect tables on the left: `cve`, `cwe`, `vendor`, `product`, `affected`, `reference`, `status_history`.

4) View data:
   - Click table **`cve`** → **Select** → run to see demo rows.

5) No-SQL filter:
   - In **Select**, set `summary` → **ILIKE** → value **%XSS%**,
   - (optional) set `severity` = **HIGH** → **Select**.

6) SQL command (copy/paste the query below) and execute:
```sql
-- Join CVEs to vendors/products; filter for XSS/HIGH; sort by recency
SELECT c.cve_id, c.summary, c.severity, c.cvss_score, c.published,
       COALESCE(string_agg(DISTINCT v.name || ':' || p.name, ', '), '-') AS products,
       c.cwe_id
FROM cve c
LEFT JOIN affected a ON a.cve_id = c.cve_id
LEFT JOIN product  p ON p.product_id = a.product_id
LEFT JOIN vendor   v ON v.vendor_id = p.vendor_id
WHERE (c.summary ILIKE '%XSS%' OR c.description ILIKE '%XSS%')
  AND c.severity = 'HIGH'
GROUP BY c.cve_id
ORDER BY c.published DESC NULLS LAST, c.cvss_score DESC NULLS LAST;

7) Export (data → CSV):
   - In **Select**, after you see results → **Export** → **CSV** → **Save**.

8) Export (schema/DDL):
   - **Export** → select **Tables** + **structure only** → **SQL** → **Save** a `.sql` with the schema.

## 9) Troubleshooting — Quick Playbook

### Connectivity & infra
```bash
# Check containers up
docker compose ps

# If DB isn't up, start it
docker compose up -d

# Inspect DB logs (last 50 lines)
docker compose logs db --tail 50

```
# Connect to PostgreSQL running in Docker from your host machine.
# -h localhost : connect via the port exposed by Docker
# -p 5432      : default PostgreSQL port exposed by compose
# -U postgres  : username (matches docker-compose)
# -d cvedb     : database name (matches .env / compose)
psql -h localhost -p 5432 -U postgres -d cvedb

# When prompted for a password, type:
# postgres

**Common issues**
- **Connection refused** → Database container is not running. Fix: `docker compose up -d`.
- **Authentication failed** → Verify `.env` values and Adminer credentials (user: `postgres`, password: `postgres`), and ensure `DB_HOST=localhost`.
- **Port 5432 already in use** → Another PostgreSQL is running locally. Stop it or change the mapping in `docker-compose.yml`.
- **psql not found** → Install PostgreSQL client tools or use Adminer (http://localhost:8080) for SQL.
- **No data returned** (empty queries) → Run the seed once: `python -m app.cli init && python -m app.cli insert-sample`.

### Python CLI issues
```bash
# Activate the project virtual environment (must be done in every new shell)
source .venv/bin/activate

# Reinstall dependencies to ensure the environment is consistent
pip install -r requirements.txt

# Sanity check: CLI entrypoints are visible
python -m app.cli --help

# If the CLI returns no rows on search, make sure the DB has tables and demo data:
python -m app.cli init           # creates tables (safe to re-run)
python -m app.cli insert-sample  # inserts 2 demo CVEs + relations (idempotent enough for dev)

### Status updates (CLI + SQL equivalent)
```bash
# Update lifecycle status and append an audit entry
python -m app.cli set-status CVE-2024-12345 Patched --note "Vendor fix confirmed"

-- Equivalent SQL (run in Adminer → SQL command)
INSERT INTO status_history(cve_id, status, note)
VALUES ('CVE-2024-12345', 'Patched', 'Vendor fix confirmed');

UPDATE cve
SET status = 'Patched'
WHERE cve_id = 'CVE-2024-12345';


### Exports & artifacts
```bash
# Ensure a dedicated folder for sample artifacts
mkdir -p samples

# Export a filtered dataset to CSV (same filters as the CLI search)
python -m app.cli export-csv --severity HIGH --outfile samples/high.csv

# Quick check the artifact exists and is readable
ls -lh samples/high.csv
head -n 5 samples/high.csv

# Note: generic CSVs are ignored by Git via .gitignore;
#       versioned examples should live under `samples/`.


### Schema dump hygiene
```bash
# Regenerate the schema-only DDL from the live database
docker compose exec -T db pg_dump -U postgres -d cvedb --schema-only > schema.sql

# Quick sanity checks on the artifact
ls -lh schema.sql
head -n 20 schema.sql

# Version the refreshed schema dump (keep it in Git for reviewers)
git add schema.sql
git commit -m "chore(db): refresh schema dump"
git push

## 10) Roadmap / Next steps

- **JSON export:** Add `export-json` alongside CSV for integrations (SIEM/SOAR pipelines).
- **NVD ingestion:** Implement `ingest_nvd.py` to batch-import NVD JSON feeds (rate-limited, resumable).
- **Analyst reports:** Add `report-stats` (e.g., monthly counts by severity, top affected vendors, average CVSS).
- **Search UX:** Support `--vendor`, `--product`, and keyword search across `references`.
- **Indexes & performance:** Add GIN index for `summary/description` (trigram) and btree on `published`, `severity`.
- **Data quality:** Validate CVE IDs format, enforce severity domain, and normalize status transitions.
- **Tests:** Unit tests for model constraints and CLI behaviors (pytest); a tiny seed fixture per test.
- **Packaging:** Ship the CLI as a Python package and/or a single Docker image (`cli` container) for zero-setup runs.
- **UI option:** Optional FastAPI + a minimal React dashboard for read-only browsing and saved queries.


