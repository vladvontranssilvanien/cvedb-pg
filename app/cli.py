import click
from datetime import date
from sqlalchemy import text, bindparam, String
from sqlalchemy.types import Integer
import requests
from datetime import datetime
from app.db import engine, SessionLocal
from app.models import Base, CVE, CWE, Vendor, Product, Affected, Reference
import csv


@click.group()
def cli():
    "CVEDB command line interface"


@cli.command()
def init():
    "Create all tables in the database"
    Base.metadata.create_all(bind=engine)
    click.secho("✅ Database initialized", fg="green")


@cli.command("insert-sample")
def insert_sample():
    "Insert two sample CVEs with vendors, products and references"
    with SessionLocal() as db:
        # CWEs
        db.add_all([
            CWE(cwe_id="CWE-79", name="Cross-site Scripting"),
            CWE(cwe_id="CWE-89", name="SQL Injection"),
        ])

        # Vendors & Products
        acme = Vendor(name="Acme")
        globex = Vendor(name="Globex")
        db.add_all([acme, globex])
        db.flush()  # get IDs

        examplecms = Product(vendor_id=acme.vendor_id, name="ExampleCMS")
        shopmaster = Product(vendor_id=globex.vendor_id, name="ShopMaster")
        db.add_all([examplecms, shopmaster])

        # CVEs
        c1 = CVE(
            cve_id="CVE-2024-12345",
            summary="ExampleCMS XSS in comments",
            description="Reflected XSS allows script injection.",
            published=date.fromisoformat("2024-06-10"),
            modified=date.fromisoformat("2024-06-15"),
            severity="HIGH",
            cvss_version="3.1",
            cvss_score=7.4,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            cwe_id="CWE-79",
            source="InternalTest",
            status="New",
        )
        c2 = CVE(
            cve_id="CVE-2025-00001",
            summary="ShopMaster SQL Injection in product filter",
            description="Improper neutralization of special elements in SQL "
            "commands.",
            published=date.fromisoformat("2025-02-05"),
            modified=date.fromisoformat("2025-02-06"),
            severity="CRITICAL",
            cvss_version="3.1",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-89",
            source="ResearchLab",
            status="Investigating",
        )
        db.add_all([c1, c2])
        db.flush()

        # Links
        db.add_all([
            Affected(cve_id=c1.cve_id, product_id=examplecms.product_id),
            Affected(cve_id=c2.cve_id, product_id=shopmaster.product_id),
        ])
        db.add_all([
            Reference(cve_id=c1.cve_id, url="https://example.com/advisories/ "
                      "2024-12345", source="vendor", tags="advisory"),
            Reference(cve_id=c2.cve_id, url="https://researchlab.example/poc",
                      source="research", tags="poc,exploit"),
        ])

        db.commit()
        click.secho("🌱 Sample data inserted", fg="green")


@cli.command()
@click.option("--keyword", help="Filter by text in summary or description")
@click.option("--severity", type=click.Choice(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False))
@click.option("--start-date", help="YYYY-MM-DD (published on or after)")
@click.option("--end-date", help="YYYY-MM-DD (published on or before)")
@click.option("--limit", default=25, type=int)
@click.option("--offset", default=0, type=int)
def search(keyword, severity, start_date, end_date, limit, offset):
    """Search CVEs with simple filters"""
    sql = text("""
SELECT
  c.cve_id, c.summary, c.severity, c.cvss_score, c.published,
  COALESCE(string_agg(DISTINCT v.name || ':' || p.name, ', '), '-') AS products,
  c.cwe_id
FROM cve c
LEFT JOIN affected a ON a.cve_id = c.cve_id
LEFT JOIN product  p ON p.product_id = a.product_id
LEFT JOIN vendor   v ON v.vendor_id = p.vendor_id
WHERE ( (:kw_like IS NULL) OR c.summary ILIKE CAST(:kw_like AS TEXT) OR c.description ILIKE CAST(:kw_like AS TEXT) )
  AND ( (:sev    IS NULL) OR c.severity = CAST(:sev AS TEXT) )
  AND ( (:start  IS NULL) OR c.published >= CAST(:start AS DATE) )
  AND ( (:end    IS NULL) OR c.published <= CAST(:end   AS DATE) )
GROUP BY c.cve_id
ORDER BY c.published DESC NULLS LAST, c.cvss_score DESC NULLS LAST
LIMIT :limit OFFSET :offset
""").bindparams(
        bindparam("kw_like", type_=String),
        bindparam("sev", type_=String),
        bindparam("start", type_=String),
        bindparam("end", type_=String),
        bindparam("limit", type_=Integer),
        bindparam("offset", type_=Integer),
    )

    kw_like = f"%{keyword}%" if keyword else None
    params = {
        "kw_like": kw_like,
        "sev": severity.upper() if severity else None,
        "start": start_date,
        "end": end_date,
        "limit": limit,
        "offset": offset,
    }
    with SessionLocal() as db:
        rows = db.execute(sql, params).mappings().all()
    for r in rows:
        print(
            f"{r['cve_id']} | {r['severity']} | CVSS {r['cvss_score']} | {r['published']} | {r['products']}\n"
            f"  {r['summary']}\n"
            f"  CWE: {r['cwe_id']}\n"
        )


@cli.command("set-status")
@click.argument("cve_id")
@click.argument("status")
@click.option("--note", default="")
def set_status(cve_id, status, note):
    "Track lifecycle status in status_history and on the CVE record"
    with SessionLocal() as db:
        db.execute(
            text("INSERT INTO status_history(cve_id,status,note) "
                 "VALUES (:id,:st,:nt)"),
            dict(id=cve_id, st=status, nt=note),
        )
        db.execute(
            text("UPDATE cve SET status=:st WHERE cve_id=:id"),
            dict(st=status, id=cve_id),
        )
        db.commit()
    click.secho("📝 Status updated", fg="green")


@cli.command("export-csv")
@click.option("--outfile", default="export.csv", help="Output CSV path")
@click.option("--keyword", help="Filter by text in summary or description")
@click.option("--severity", type=click.Choice(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False))
@click.option("--start-date", help="YYYY-MM-DD (published on or after)")
@click.option("--end-date", help="YYYY-MM-DD (published on or before)")
def export_csv(outfile, keyword, severity, start_date, end_date):
    """Export search results to CSV (same filters as `search`)"""
    sql = text("""
SELECT
  c.cve_id, c.summary, c.severity, c.cvss_score, c.published, c.status,
  COALESCE(string_agg(DISTINCT v.name || ':' || p.name, ', '), '-') AS products,
  c.cwe_id
FROM cve c
LEFT JOIN affected a ON a.cve_id = c.cve_id
LEFT JOIN product  p ON p.product_id = a.product_id
LEFT JOIN vendor   v ON v.vendor_id = p.vendor_id
WHERE ( (:kw_like IS NULL) OR c.summary ILIKE CAST(:kw_like AS TEXT) OR c.description ILIKE CAST(:kw_like AS TEXT) )
  AND ( (:sev    IS NULL) OR c.severity = CAST(:sev AS TEXT) )
  AND ( (:start  IS NULL) OR c.published >= CAST(:start AS DATE) )
  AND ( (:end    IS NULL) OR c.published <= CAST(:end   AS DATE) )
GROUP BY c.cve_id
ORDER BY c.published DESC NULLS LAST, c.cvss_score DESC NULLS LAST
""").bindparams(
        bindparam("kw_like", type_=String),
        bindparam("sev", type_=String),
        bindparam("start", type_=String),
        bindparam("end", type_=String),
    )

    kw_like = f"%{keyword}%" if keyword else None
    params = {
        "kw_like": kw_like,
        "sev": severity.upper() if severity else None,
        "start": start_date,
        "end": end_date,
    }
    with SessionLocal() as db, open(outfile, "w", newline="", encoding="utf-8") as f:
        rows = db.execute(sql, params).mappings().all()
        writer = csv.writer(f)
        writer.writerow([
            "cve_id", "summary", "severity", "cvss_score",
            "published", "status", "products", "cwe_id"
        ])
        for r in rows:
            writer.writerow([
                r["cve_id"], r["summary"], r["severity"], r["cvss_score"],
                r["published"], r["status"], r["products"], r["cwe_id"]
            ])
    click.secho(f"📦 Exported {len(rows)} rows -> {outfile}", fg="green")


@cli.command("ingest-cve")
@click.argument("cve_id")
def ingest_cve(cve_id):
    """
    Fetch one CVE by ID from NVD (v2.0) "
    "and upsert basic fields into our schema.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        res = requests.get(url, timeout=30)
        res.raise_for_status()
        data = res.json()
    except Exception as e:
        click.secho(f"HTTP/parse error: {e}", fg="red")
        return

    vulns = data.get("vulnerabilities") or data.get("vulns") or []
    if not vulns:
        click.secho("CVE not found in NVD.", fg="yellow")
        return

    v = vulns[0]["cve"]

    # helpers
    def pick_cvss(m):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = m.get(key) or []
            if arr:
                item = arr[0]
                dv = item.get("cvssData", {})
                return (
                    dv.get("version") or (
                        "3.1" if key.endswith("V31") else "3.0"
                        if key.endswith("V30") else "2.0"),
                    item.get("baseSeverity") or dv.get("baseSeverity"),
                    item.get("baseScore") or dv.get("baseScore"),
                    dv.get("vectorString") or item.get("vectorString"),
                )
        return (None, None, None, None)

    def to_date(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        except Exception:
            return None

    # map
    summary = None
    for d in v.get("descriptions", []):
        if d.get("lang") == "en":
            summary = d.get("value")
            break
    summary = summary or (v.get("descriptions", [{}])[0].get("value")
                          if v.get("descriptions") else "")

    cwe_id = None
    for w in v.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value") or ""
            if val.startswith("CWE-"):
                cwe_id = val
                break
        if cwe_id:
            break

    published = to_date(v.get("published"))
    modified = to_date(v.get("lastModified"))

    version, severity, score, vector = pick_cvss(v.get("metrics", {}))

    # upsert in DB
    with SessionLocal() as db:
        if cwe_id:
            db.merge(CWE(cwe_id=cwe_id, name=cwe_id))

        db.merge(CVE(
            cve_id=cve_id,
            summary=summary or "",
            description=summary or "",
            published=published,
            modified=modified,
            severity=severity,
            cvss_version=version,
            cvss_score=score,
            cvss_vector=vector,
            cwe_id=cwe_id,
            source="NVD",
            status="New",
        ))

        db.flush()

        seen = set()
        for r in v.get("references", []):
            ref_url = (r.get("url") or "").strip()
            if not ref_url or ref_url in seen:
                continue
            seen.add(ref_url)

            ref_source = "nvd"
            ref_tags = ",".join(r.get("tags", [])) if r.get("tags") else None

            db.execute(
                text("""
                    INSERT INTO reference (cve_id, url, source, tags)
                    VALUES (:cve_id, :url, :source, :tags)
                    ON CONFLICT (cve_id, url) DO NOTHING
                """),
                {"cve_id": cve_id, "url": ref_url, "source":
                    ref_source, "tags": ref_tags}
            )

        db.commit()

    click.secho(f"✅ Ingested {cve_id} from NVD", fg="green")


if __name__ == "__main__":
    cli()
