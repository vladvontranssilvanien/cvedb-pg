import click
from datetime import date
from sqlalchemy import text

from app.db import engine, SessionLocal
from app.models import Base, CVE, CWE, Vendor, Product, Affected, Reference, StatusHistory
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
            description="Improper neutralization of special elements in SQL commands.",
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
            Reference(cve_id=c1.cve_id, url="https://example.com/advisories/2024-12345", source="vendor", tags="advisory"),
            Reference(cve_id=c2.cve_id, url="https://researchlab.example/poc", source="research", tags="poc,exploit"),
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
    "Search CVEs with simple filters"
    sql = """
    SELECT
      c.cve_id, c.summary, c.severity, c.cvss_score, c.published,
      COALESCE(string_agg(DISTINCT v.name || ':' || p.name, ', '), '-') AS products,
      c.cwe_id
    FROM cve c
    LEFT JOIN affected a ON a.cve_id = c.cve_id
    LEFT JOIN product  p ON p.product_id = a.product_id
    LEFT JOIN vendor   v ON v.vendor_id = p.vendor_id
    WHERE ( c.summary ILIKE CAST(:kw_like AS TEXT) OR c.description ILIKE CAST(:kw_like AS TEXT) OR :kw_like IS NULL )
      AND ( c.severity = CAST(:sev AS TEXT) OR :sev IS NULL )
      AND ( c.published >= CAST(:start AS DATE) OR :start IS NULL )
      AND ( c.published <= CAST(:end   AS DATE) OR :end IS NULL )
    GROUP BY c.cve_id
    ORDER BY c.published DESC NULLS LAST, c.cvss_score DESC NULLS LAST
    LIMIT :limit OFFSET :offset
    """
    kw_like = f"%{keyword}%" if keyword else None
    params = dict(
        kw_like=kw_like,
        sev=severity.upper() if severity else None,
        start=start_date,
        end=end_date,
        limit=limit,
        offset=offset,
    )

    with SessionLocal() as db:
        rows = db.execute(text(sql), params).mappings().all()
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
            text("INSERT INTO status_history(cve_id,status,note) VALUES (:id,:st,:nt)"),
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
    "Export search results to CSV (same filters as `search`)"
    sql = """
    SELECT
      c.cve_id, c.summary, c.severity, c.cvss_score, c.published, c.status,
      COALESCE(string_agg(DISTINCT v.name || ':' || p.name, ', '), '-') AS products,
      c.cwe_id
    FROM cve c
    LEFT JOIN affected a ON a.cve_id = c.cve_id
    LEFT JOIN product  p ON p.product_id = a.product_id
    LEFT JOIN vendor   v ON v.vendor_id = p.vendor_id
    WHERE ( c.summary ILIKE CAST(:kw_like AS TEXT) OR c.description ILIKE CAST(:kw_like AS TEXT) OR :kw_like IS NULL )
      AND ( c.severity = CAST(:sev AS TEXT) OR :sev IS NULL )
      AND ( c.published >= CAST(:start AS DATE) OR :start IS NULL )
      AND ( c.published <= CAST(:end   AS DATE) OR :end   IS NULL )
    GROUP BY c.cve_id
    ORDER BY c.published DESC NULLS LAST, c.cvss_score DESC NULLS LAST
    """
    kw_like = f"%{keyword}%" if keyword else None
    params = dict(
        kw_like=kw_like,
        sev=severity.upper() if severity else None,
        start=start_date,
        end=end_date,
    )
    with SessionLocal() as db, open(outfile, "w", newline="", encoding="utf-8") as f:
        rows = db.execute(text(sql), params).mappings().all()
        writer = csv.writer(f)
        writer.writerow(["cve_id", "summary", "severity", "cvss_score",
                         "published", "status", "products", "cwe_id"])
        for r in rows:
            writer.writerow([
                r["cve_id"], r["summary"], r["severity"], r["cvss_score"],
                r["published"], r["status"], r["products"], r["cwe_id"]
            ])
    click.secho(f"📦 Exported {len(rows)} rows -> {outfile}", fg="green")


if __name__ == "__main__":
    cli()
