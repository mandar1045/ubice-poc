#!/usr/bin/env python3
"""
UBICE Full Pipeline Demo
========================
GSoC 2026 | Mandar Joshi | FOSSology

Demonstrates the full UBICE analysis pipeline:
  1. ELF feature extraction (Module 2)
  2. Bloom filter pre-screening (Module 3 Stage 1)
  3. CSD SQLite lookup with TLSH fuzzy matching (Module 3 Stage 1)
  4. SPDX 2.3 SBOM generation (Module 5)

Usage:
    python3 demo.py /bin/ls
    python3 demo.py /lib/x86_64-linux-gnu/libc.so.6
    python3 demo.py /path/to/your/binary
"""
import argparse
import json
import os
import sys

from ubice.extractor.elf import extract
from ubice.fingerprint.bloom import BloomFilter
from ubice.fingerprint.csd import CSD
from ubice.sbom.spdx import SPDXDocument


SEPARATOR = "─" * 64


def build_bloom_from_csd(csd: CSD) -> BloomFilter:
    bf = BloomFilter.optimal(expected_items=10_000, fpr=0.01)
    con = csd._con
    rows = con.execute(
        "SELECT tlsh_hash, sha256, build_id FROM binary_signature"
    ).fetchall()
    for row in rows:
        for val in (row["tlsh_hash"], row["sha256"], row["build_id"]):
            if val:
                bf.add(val)
    return bf


def run_pipeline(binary_path: str, emit_sbom: bool = True) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  UBICE Analysis Pipeline — {os.path.basename(binary_path)}")
    print(SEPARATOR)

    # -- Step 1: Feature Extraction ------------------------------------------
    print("\n[1/4] ELF Feature Extraction")
    try:
        fv = extract(binary_path)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)

    print(f"  Architecture   : {fv.arch} ({fv.bits}-bit)")
    print(f"  SHA-256        : {fv.sha256[:32]}...")
    print(f"  TLSH Hash      : {fv.tlsh_hash or '(python-tlsh not installed)'}")
    print(f"  Build-ID       : {fv.build_id or '(none)'}")
    print(f"  Exported syms  : {fv.symbol_count}")
    print(f"  Imported syms  : {len(fv.imported_symbols)}")
    print(f"  Sections       : {len(fv.section_sizes)}")
    top_sections = sorted(fv.section_sizes.items(), key=lambda x: -x[1])[:4]
    for name, size in top_sections:
        print(f"    {name:<20} {size:>10,} bytes")

    # -- Step 2: Bloom Filter Pre-screen -------------------------------------
    print("\n[2/4] Bloom Filter Pre-screen")
    csd = CSD.open(":memory:")   # in-memory for demo; real use: file-backed
    csd.seed_demo_data()
    print(f"  CSD entries    : {csd.row_count()}")

    bf = build_bloom_from_csd(csd)
    print(f"  Bloom size     : {bf._n // 8 // 1024} KB, {bf._k} hashes, "
          f"estimated FPR={bf.estimated_fpr:.4%}")

    bloom_hit = False
    for val in (fv.sha256, fv.build_id, fv.tlsh_hash):
        if val and val in bf:
            bloom_hit = True
            break
    print(f"  Bloom decision : {'HIT -> proceed to CSD lookup' if bloom_hit else 'MISS -> skip lookup (not in known signatures)'}")

    # -- Step 3: CSD Lookup --------------------------------------------------
    print("\n[3/4] CSD Lookup")
    match = None

    if fv.sha256:
        match = csd.lookup_sha256(fv.sha256)
        if match:
            print(f"  SHA-256 exact match: {match.package_name} {match.version}")

    if not match and fv.build_id:
        match = csd.lookup_build_id(fv.build_id)
        if match:
            print(f"  Build-ID exact match: {match.package_name} {match.version}")

    if not match and fv.tlsh_hash:
        match = csd.lookup_tlsh(fv.tlsh_hash, max_distance=30)
        if match:
            print(f"  TLSH fuzzy match: {match.package_name} {match.version} "
                  f"(distance={match.tlsh_distance}, confidence={match.confidence_pct}%)")

    if not match:
        print("  No match found in demo CSD — binary not in seed dataset")
        print("  (In production CSD will cover 3,000+ packages across 6 ecosystems)")
    else:
        print(f"\n  +-- Component Identified --------------------------------+")
        print(f"  |  Package  : {match.package_name:<35}|")
        print(f"  |  Version  : {match.version:<35}|")
        print(f"  |  PURL     : {match.purl:<35}|")
        print(f"  |  License  : {match.license_spdx or 'NOASSERTION':<35}|")
        print(f"  |  Stage    : {match.match_stage:<35}|")
        print(f"  |  Conf.    : {match.confidence_pct}%{'':<33}|")
        print(f"  +--------------------------------------------------------+")

    # -- Step 4: SBOM Generation ---------------------------------------------
    print("\n[4/4] SPDX 2.3 SBOM Generation")
    if match and emit_sbom:
        doc = SPDXDocument(name=os.path.basename(binary_path))
        doc.add_component(match, fv)
        sbom_json = doc.to_json()
        out_path = f"{os.path.basename(binary_path)}.spdx.json"
        with open(out_path, "w") as fh:
            fh.write(sbom_json)
        print(f"  SPDX 2.3 SBOM written -> {out_path}")
        sbom = json.loads(sbom_json)
        print(f"  spdxVersion    : {sbom['spdxVersion']}")
        print(f"  packages       : {len(sbom['packages'])}")
        print(f"  relationships  : {len(sbom['relationships'])}")
    else:
        print("  (no SBOM generated — no component identified)")

    print(f"\n{SEPARATOR}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UBICE Full Pipeline Demo — ELF -> CSD -> SBOM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("binary", help="Path to an ELF binary to analyse")
    parser.add_argument("--no-sbom", action="store_true",
                        help="Skip SPDX SBOM generation")
    args = parser.parse_args()
    run_pipeline(args.binary, emit_sbom=not args.no_sbom)


if __name__ == "__main__":
    main()
