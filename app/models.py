from sqlalchemy import (
    String, Integer, Float, Date, DateTime, Text, ForeignKey, Boolean,
    UniqueConstraint, Index, func
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB
from datetime import date, datetime

class Base(DeclarativeBase):
    pass

class CWE(Base):
    __tablename__ = "cwe"
    cwe_id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)

class CVE(Base):
    __tablename__ = "cve"
    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    published: Mapped[date | None] = mapped_column(Date, nullable=True)
    modified: Mapped[date | None] = mapped_column(Date, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String, ForeignKey("cwe.cwe_id"), nullable=True)
    source: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="New")

    cwe: Mapped["CWE"] = relationship(backref="cves")
    references: Mapped[list["Reference"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    affected: Mapped[list["Affected"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    raw: Mapped[list["RawNVD"]] = relationship(back_populates="cve", cascade="all, delete-orphan")

# helpful indexes
Index("idx_cve_published", CVE.published)
Index("idx_cve_severity", CVE.severity)
Index("idx_cve_cwe", CVE.cwe_id)

class Vendor(Base):
    __tablename__ = "vendor"
    vendor_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)

class Product(Base):
    __tablename__ = "product"
    product_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vendor_id: Mapped[int] = mapped_column(Integer, ForeignKey("vendor.vendor_id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)

    vendor: Mapped["Vendor"] = relationship(backref="products")
    __table_args__ = (UniqueConstraint("vendor_id", "name", name="uq_vendor_product"),)

Index("idx_product_name", Product.name)

class Affected(Base):
    __tablename__ = "affected"
    cve_id: Mapped[str] = mapped_column(String, ForeignKey("cve.cve_id", ondelete="CASCADE"), primary_key=True)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("product.product_id", ondelete="CASCADE"), primary_key=True)
    version_min: Mapped[str | None] = mapped_column(String, nullable=True)
    version_max: Mapped[str | None] = mapped_column(String, nullable=True)
    include_min: Mapped[bool] = mapped_column(Boolean, default=True)
    include_max: Mapped[bool] = mapped_column(Boolean, default=False)

    cve: Mapped["CVE"] = relationship(back_populates="affected")
    product: Mapped["Product"] = relationship()

Index("idx_affected_product", Affected.product_id)

class Reference(Base):
    __tablename__ = "reference"
    ref_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String, ForeignKey("cve.cve_id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[str | None] = mapped_column(String, nullable=True)

    cve: Mapped["CVE"] = relationship(back_populates="references")

class StatusHistory(Base):
    __tablename__ = "status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String, ForeignKey("cve.cve_id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

class RawNVD(Base):
    __tablename__ = "raw_nvd"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String, ForeignKey("cve.cve_id", ondelete="CASCADE"))
    payload: Mapped[dict] = mapped_column(JSONB)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    cve: Mapped["CVE"] = relationship(back_populates="raw")
