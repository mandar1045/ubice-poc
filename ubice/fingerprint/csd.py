"""
ubice.fingerprint.csd
~~~~~~~~~~~~~~~~~~~~~
Component Signature Database (CSD) — SQLite-backed lookup for Stage 1 fingerprinting.

Schema mirrors the production UBICE proposal schema from the GSoC document.

Usage::

    csd = CSD.open("csd.db")
    csd.seed_demo_data()

    result = csd.lookup_sha256("abc123...")
    result = csd.lookup_build_id("8b3e9c1a...")
    result = csd.lookup_tlsh("T1A3F2...", max_distance=30)
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["ComponentMatch", "CSD"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS binary_signature (
    bs_pk         INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name  TEXT    NOT NULL,
    version       TEXT    NOT NULL,
    ecosystem     TEXT    NOT NULL DEFAULT 'debian',
    purl          TEXT    UNIQUE NOT NULL,
    license_spdx  TEXT,
    sha256        TEXT    UNIQUE,
    tlsh_hash     TEXT,
    build_id      TEXT,
    symbol_count  INTEGER DEFAULT 0,
    created_at    TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sha256   ON binary_signature(sha256);
CREATE INDEX IF NOT EXISTS idx_build_id ON binary_signature(build_id);
CREATE INDEX IF NOT EXISTS idx_tlsh     ON binary_signature(tlsh_hash);
"""

# Demo seed data — representative entries for well-known Debian packages
_DEMO_SEED = [
    {
        "package_name": "coreutils",
        "version": "8.32-4.1+b1",
        "ecosystem": "debian",
        "purl": "pkg:deb/debian/coreutils@8.32-4.1+b1",
        "license_spdx": "GPL-3.0-or-later",
        "sha256": None,
        "tlsh_hash": "T1A3F256D8C3E1A9B2D4F5C6E7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6",
        "build_id": None,
        "symbol_count": 47,
    },
    {
        "package_name": "libssl3",
        "version": "3.0.2-0ubuntu1",
        "ecosystem": "ubuntu",
        "purl": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1",
        "license_spdx": "Apache-2.0 AND OpenSSL",
        "sha256": None,
        "tlsh_hash": "T2B4E367F9D5A2C8E1B3D6F8A0C2E4F6A8B0D2E4F6A8C0E2A4C6E8A0C2E4F6A8",
        "build_id": None,
        "symbol_count": 312,
    },
    {
        "package_name": "libc6",
        "version": "2.35-0ubuntu3",
        "ecosystem": "ubuntu",
        "purl": "pkg:deb/ubuntu/libc6@2.35-0ubuntu3",
        "license_spdx": "LGPL-2.1-or-later",
        "sha256": None,
        "tlsh_hash": "T3C5F478A0E6B3D9F2C4E7A9B1D3F5A7C9E1A3C5E7A9C1E3A5C7E9A1C3E5A7C9",
        "build_id": None,
        "symbol_count": 1028,
    },
    {
        "package_name": "zlib1g",
        "version": "1:1.2.11.dfsg-2",
        "ecosystem": "debian",
        "purl": "pkg:deb/debian/zlib1g@1.2.11.dfsg-2",
        "license_spdx": "Zlib",
        "sha256": None,
        "tlsh_hash": "T4D6A589B1F7C4E0A3D5G8B0D2F4A6C8E0B2D4F6A8C0E2A4C6E8B0D2F4A6C8E0",
        "build_id": None,
        "symbol_count": 89,
    },
]


@dataclass
class ComponentMatch:
    """A fingerprinting match returned from CSD lookup."""
    package_name: str
    version: str
    purl: str
    license_spdx: Optional[str]
    match_stage: int          # 1=sha256/build-id exact, 2=tlsh fuzzy
    confidence_pct: int       # 0-100
    tlsh_distance: Optional[int] = None

    def as_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "purl": self.purl,
            "license_spdx": self.license_spdx,
            "match_stage": self.match_stage,
            "confidence_pct": self.confidence_pct,
            "tlsh_distance": self.tlsh_distance,
        }


class CSD:
    """Thin wrapper around the Component Signature Database SQLite file."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._con = sqlite3.connect(str(self._path))
        self._con.row_factory = sqlite3.Row
        self._con.executescript(_SCHEMA)
        self._con.commit()

    @classmethod
    def open(cls, db_path: str | Path = "csd.db") -> "CSD":
        return cls(db_path)

    def seed_demo_data(self) -> int:
        """Insert representative demo entries. Returns number of rows inserted."""
        inserted = 0
        for row in _DEMO_SEED:
            try:
                self._con.execute(
                    """INSERT OR IGNORE INTO binary_signature
                       (package_name, version, ecosystem, purl, license_spdx,
                        sha256, tlsh_hash, build_id, symbol_count)
                       VALUES (:package_name, :version, :ecosystem, :purl,
                               :license_spdx, :sha256, :tlsh_hash, :build_id,
                               :symbol_count)""",
                    row,
                )
                inserted += self._con.execute("SELECT changes()").fetchone()[0]
            except sqlite3.IntegrityError:
                pass
        self._con.commit()
        return inserted

    def lookup_sha256(self, sha256: str) -> Optional[ComponentMatch]:
        row = self._con.execute(
            "SELECT * FROM binary_signature WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row:
            return ComponentMatch(
                package_name=row["package_name"], version=row["version"],
                purl=row["purl"], license_spdx=row["license_spdx"],
                match_stage=1, confidence_pct=100,
            )
        return None

    def lookup_build_id(self, build_id: str) -> Optional[ComponentMatch]:
        row = self._con.execute(
            "SELECT * FROM binary_signature WHERE build_id = ?", (build_id,)
        ).fetchone()
        if row:
            return ComponentMatch(
                package_name=row["package_name"], version=row["version"],
                purl=row["purl"], license_spdx=row["license_spdx"],
                match_stage=1, confidence_pct=100,
            )
        return None

    def lookup_tlsh(self, tlsh_hash: str, max_distance: int = 30) -> Optional[ComponentMatch]:
        """
        Linear scan with TLSH distance check.
        In production this is pre-filtered by the Bloom filter and uses an index.
        """
        try:
            import tlsh as tlsh_mod
        except ImportError:
            return None

        rows = self._con.execute(
            "SELECT * FROM binary_signature WHERE tlsh_hash IS NOT NULL"
        ).fetchall()

        best_match = None
        best_dist = max_distance + 1
        for row in rows:
            try:
                dist = tlsh_mod.diff(tlsh_hash, row["tlsh_hash"])
            except Exception:
                continue
            if dist < best_dist:
                best_dist = dist
                best_match = row

        if best_match:
            confidence = max(0, 100 - (best_dist * 3))
            return ComponentMatch(
                package_name=best_match["package_name"],
                version=best_match["version"],
                purl=best_match["purl"],
                license_spdx=best_match["license_spdx"],
                match_stage=2,
                confidence_pct=confidence,
                tlsh_distance=best_dist,
            )
        return None

    def row_count(self) -> int:
        return self._con.execute("SELECT COUNT(*) FROM binary_signature").fetchone()[0]

    def close(self) -> None:
        self._con.close()
