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


