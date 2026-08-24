"""SQLite-backed persistence (PostgreSQL-compatible via SQLAlchemy)."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import (Column, DateTime, Float, Integer, String, Text,
                         create_engine)
from sqlalchemy.orm import declarative_base, sessionmaker

DB_DIR = Path(os.path.expanduser("~/.dracxx"))
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = os.environ.get("DRACXX_DB", str(DB_DIR / "dracxx.db"))

Base = declarative_base()


class ScanSessionRow(Base):
    __tablename__ = "scan_sessions"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, unique=True, index=True)
    target = Column(String)
    profile = Column(String)
    scope_json = Column(Text)
    tool_versions_json = Column(Text)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)


class AssetRow(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    target = Column(String, index=True)
    asset_type = Column(String)
    ip = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    source = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)


class FindingRow(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    finding_id = Column(String, index=True)
    title = Column(String)
    severity = Column(String)
    confidence = Column(String)
    target = Column(String)
    asset = Column(String)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    technology = Column(String, nullable=True)
    version = Column(String, nullable=True)
    cpe = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)
    scanner = Column(String)
    references_json = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cves_json = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


class AIAnalysisRow(Base):
    __tablename__ = "ai_analysis"
    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    finding_id = Column(String, index=True, nullable=True)
    content = Column(Text)
    provider = Column(String)
    model = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


_engine = create_engine(f"sqlite:///{DB_PATH}", future=True)
SessionLocal = sessionmaker(bind=_engine, future=True)


def init_db():
    Base.metadata.create_all(_engine)
    return DB_PATH


def get_session():
    return SessionLocal()
