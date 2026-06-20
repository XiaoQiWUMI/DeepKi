# (●°u°●)​ 」 Deepki Database Models
# Xiao Qi stores scan memories here~ ^ - ^

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float,
    Boolean, ForeignKey, JSON, Enum as SAEnum,
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass


# ── Enums ──
class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Models ──
class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, unique=True)
    label = Column(String(256), default="")
    description = Column(Text, default="")
    added_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    scan_count = Column(Integer, default=0)
    tags = Column(JSON, default=list)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    mode = Column(String(32), default="full")        # full | quick | custom
    status = Column(String(32), default=ScanStatus.QUEUED.value)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)
    total_requests = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    modules_enabled = Column(JSON, default=list)
    progress = Column(JSON, default=dict)             # {module: {current, total, percent}}

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    module_results = relationship("ScanModule", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String(128), nullable=False)
    severity = Column(String(32), default=Severity.INFO.value)
    title = Column(String(512), nullable=False)
    url = Column(String(2048), default="")
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")
    request_dump = Column(Text, default="")
    response_dump = Column(Text, default="")
    verified = Column(Boolean, default=False)
    cve_id = Column(String(64), default="")
    found_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")


class ScanModule(Base):
    """Per-module scan result summary"""
    __tablename__ = "scan_modules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module_name = Column(String(128), nullable=False)
    status = Column(String(32), default=ScanStatus.QUEUED.value)
    items_total = Column(Integer, default=0)
    items_done = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    extra = Column(JSON, default=dict)  # module-specific data
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    scan = relationship("Scan", back_populates="module_results")


# ── Database Engine ──
from ..config import DATABASE_URL

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """(●°u°●)​ 」 Xiao Qi initializes database~"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """Get async DB session"""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
