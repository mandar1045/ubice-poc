"""Tests for ubice.fingerprint.csd."""
import pytest
from ubice.fingerprint.csd import CSD, ComponentMatch


@pytest.fixture
def csd():
    db = CSD.open(":memory:")
    db.seed_demo_data()
    return db


def test_seed_inserts_rows(csd):
    assert csd.row_count() >= 1


def test_lookup_sha256_miss(csd):
    assert csd.lookup_sha256("0" * 64) is None


def test_lookup_build_id_miss(csd):
    assert csd.lookup_build_id("nonexistent") is None


def test_seed_is_idempotent(csd):
    count_before = csd.row_count()
    csd.seed_demo_data()   # second call should not insert duplicates
    assert csd.row_count() == count_before


def test_component_match_as_dict(csd):
    # Just verify the as_dict helper works
    rows = csd._con.execute("SELECT * FROM binary_signature LIMIT 1").fetchone()
    match = ComponentMatch(
        package_name=rows["package_name"],
        version=rows["version"],
        purl=rows["purl"],
        license_spdx=rows["license_spdx"],
        match_stage=1,
        confidence_pct=100,
    )
    d = match.as_dict()
    assert d["package_name"] == rows["package_name"]
    assert d["match_stage"] == 1
