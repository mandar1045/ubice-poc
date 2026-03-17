"""Tests for ubice.sbom.spdx."""
import json
from ubice.sbom.spdx import SPDXDocument
from ubice.fingerprint.csd import ComponentMatch


def _make_match():
    return ComponentMatch(
        package_name="zlib1g",
        version="1.2.11",
        purl="pkg:deb/debian/zlib1g@1.2.11",
        license_spdx="Zlib",
        match_stage=1,
        confidence_pct=100,
    )


def test_to_json_valid():
    doc = SPDXDocument(name="test-firmware")
    doc.add_component(_make_match())
    raw = doc.to_json()
    data = json.loads(raw)
    assert data["spdxVersion"] == "SPDX-2.3"
    assert len(data["packages"]) == 1
    assert data["packages"][0]["name"] == "zlib1g"


def test_purl_external_ref():
    doc = SPDXDocument(name="test-firmware")
    doc.add_component(_make_match())
    data = doc.to_dict()
    ext_refs = data["packages"][0]["externalRefs"]
    assert any(ref["referenceType"] == "purl" for ref in ext_refs)


def test_multiple_components():
    doc = SPDXDocument(name="test-firmware")
    m1 = _make_match()
    m2 = ComponentMatch("openssl", "3.0.2", "pkg:deb/ubuntu/openssl@3.0.2",
                        "Apache-2.0", 2, 85, tlsh_distance=12)
    doc.add_component(m1)
    doc.add_component(m2)
    data = doc.to_dict()
    assert len(data["packages"]) == 2
    assert len(data["relationships"]) == 2
