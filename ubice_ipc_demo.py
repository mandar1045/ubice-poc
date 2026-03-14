#!/usr/bin/env python3
"""
ubice_ipc_demo.py  —  UBICE Proof of Concept
GSoC 2026 | Mandar Joshi

Demonstrates two things:
  1. FOSSology scheduler IPC  — reads ITEM/CLOSE from stdin, writes OK back,
     exactly like nomos or monk would, but from Python.
  2. ELF fingerprinting       — extracts symbols + TLSH hash from a real ELF
     binary and produces a ComponentCandidate dict.

Run in scheduler-IPC mode:
    echo -e "ITEM 42\nCLOSE" | python3 ubice_ipc_demo.py --mode ipc

Run fingerprint demo on any ELF:
    python3 ubice_ipc_demo.py --mode fingerprint --binary /bin/ls

Dependencies:  pyelftools  tlsh  (pip install pyelftools python-tlsh)
"""

import sys
import argparse
import hashlib
import os


# ── 1. FOSSology Scheduler IPC Demo ──────────────────────────────────────────

def scheduler_ipc_loop():
    """
    Implements the FOSSology ITEM/OK/CLOSE protocol over stdin/stdout.
    This is the same loop that every C agent (nomos, monk, ojo) runs —
    UBICE just does it from Python instead of C.

    Protocol (from src/lib/c/libfossscheduler.h):
        Scheduler sends:  ITEM <upload_pk>
        Agent replies:    OK <upload_pk>
        Scheduler sends:  CLOSE   (when done)
        Agent exits cleanly.
    """
    print("[ubice-demo] agent started, waiting for scheduler input", flush=True)

    for raw_line in sys.stdin:
        line = raw_line.strip()

        if not line:
            continue

        if line == "CLOSE":
            print("[ubice-demo] received CLOSE, exiting cleanly", flush=True)
            break

        if line.startswith("ITEM"):
            parts = line.split()
            upload_pk = int(parts[1]) if len(parts) > 1 else -1
            print(f"[ubice-demo] processing upload_pk={upload_pk}", flush=True)

            # In real code this is where process_upload(upload_pk) runs.
            # Here we just simulate it with a short sleep-less stub.
            result = _stub_process(upload_pk)
            print(f"[ubice-demo] result: {result}", flush=True)

            # ACK back to scheduler — this is the required response
            print(f"OK {upload_pk}", flush=True)

        elif line.startswith("VERBOSE"):
            # Scheduler can ask agents to print extra debug info
            pass

        else:
            print(f"[ubice-demo] unknown token: {line!r}", flush=True)


def _stub_process(upload_pk: int) -> dict:
    """Stub — in real ubice-unpack this unpacks OCI layers / SquashFS / ELF."""
    return {
        "upload_pk": upload_pk,
        "status": "unpacked",
        "files_written": 0,   # would be actual uploadtree row count
    }


# ── 2. ELF Fingerprinting Demo ────────────────────────────────────────────────

def fingerprint_elf(binary_path: str) -> dict:
    """
    Extracts a feature vector from an ELF binary and computes a TLSH hash
    for fuzzy matching against the Component Signature Database (CSD).

    This is the core of UBICE Module 2 (Feature Extraction) and the first
    stage of Module 3 (Fingerprinting).
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        print("ERROR: pyelftools not installed. Run: pip install pyelftools")
        sys.exit(1)

    try:
        import tlsh
        has_tlsh = True
    except ImportError:
        print("WARNING: python-tlsh not installed. TLSH hash will be skipped.")
        print("         Install with: pip install python-tlsh")
        has_tlsh = False

    if not os.path.isfile(binary_path):
        print(f"ERROR: file not found: {binary_path}")
        sys.exit(1)

    feature_vector = {
        "binary": binary_path,
        "arch": None,
        "bits": None,
        "build_id": None,
        "exported_symbols": [],
        "section_sizes": {},
        "sha256": None,
        "tlsh_hash": None,
        "candidate": None,
    }

    # SHA-256 of the whole file (for exact-match fast path)
    with open(binary_path, "rb") as fh:
        raw = fh.read()
    feature_vector["sha256"] = hashlib.sha256(raw).hexdigest()

    # TLSH fuzzy hash — tolerant of minor version differences
    if has_tlsh:
        h = tlsh.hash(raw)
        feature_vector["tlsh_hash"] = h

    # ELF parsing
    with open(binary_path, "rb") as fh:
        try:
            elf = ELFFile(fh)
        except Exception as exc:
            print(f"ERROR: not a valid ELF file ({exc})")
            sys.exit(1)

        feature_vector["arch"] = elf.get_machine_arch()
        feature_vector["bits"] = elf.elfclass

        # Section sizes (key fingerprinting signal — changes less than symbols)
        for section in elf.iter_sections():
            if section.name and section['sh_size'] > 0:
                feature_vector["section_sizes"][section.name] = section['sh_size']

        # Exported symbol names (for SimHash / symbol-bag matching)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                # Only exported (global/weak) defined symbols
                bind = sym.entry.st_info.bind
                vis  = sym.entry.st_other.visibility
                if (sym.name
                        and sym.entry.st_size > 0
                        and bind in ("STB_GLOBAL", "STB_WEAK")
                        and vis  in ("STV_DEFAULT", "STV_PROTECTED")):
                    feature_vector["exported_symbols"].append(sym.name)

        # GNU Build-ID (strongest single identifier when present)
        for section in elf.iter_sections():
            if section.name == ".note.gnu.build-id":
                data = section.data()
                # Note structure: namesz(4) descsz(4) type(4) name desc
                if len(data) > 12:
                    namesz = int.from_bytes(data[0:4], "little")
                    descsz = int.from_bytes(data[4:8], "little")
                    desc_offset = 12 + namesz
                    desc_offset = (desc_offset + 3) & ~3  # align to 4 bytes
                    build_id = data[desc_offset: desc_offset + descsz]
                    feature_vector["build_id"] = build_id.hex()

    # Simulated CSD lookup (in real code this queries csd.db via TLSH distance)
    feature_vector["candidate"] = _mock_csd_lookup(feature_vector)

    return feature_vector


def _mock_csd_lookup(fv: dict) -> dict | None:
    """
    Simulates a Stage 1 Bloom-filter + TLSH lookup against the CSD.
    In the real implementation this does:
        1. bloom.bin.contains(tlsh_hash)   — O(1) filter
        2. If HIT: SELECT * FROM binary_signature WHERE tlsh_distance(hash, ?) < 30
    """
    # Fake a hit for demo purposes — real code queries csd.db
    if fv["build_id"]:
        return {
            "name": "<would be looked up from csd.db>",
            "version": "?",
            "purl": "pkg:unknown/demo",
            "license_spdx": "?",
            "match_stage": 1,
            "confidence_pct": 0,
            "note": "Build-ID present — Stage 1 exact match possible",
        }
    if fv["exported_symbols"]:
        return {
            "name": "<symbol-bag match>",
            "version": "?",
            "purl": "pkg:unknown/demo",
            "license_spdx": "?",
            "match_stage": 2,
            "confidence_pct": 0,
            "note": f"{len(fv['exported_symbols'])} exported symbols found, "
                    "would be fed into SimHash + TLSH distance check",
        }
    return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UBICE PoC — scheduler IPC demo + ELF fingerprinting")
    parser.add_argument("--mode", choices=["ipc", "fingerprint"],
                        required=True,
                        help="ipc: simulate scheduler loop | "
                             "fingerprint: extract ELF feature vector")
    parser.add_argument("--binary", metavar="PATH",
                        help="path to ELF binary (required for --mode fingerprint)")
    args = parser.parse_args()

    if args.mode == "ipc":
        scheduler_ipc_loop()

    elif args.mode == "fingerprint":
        if not args.binary:
            print("ERROR: --binary PATH required for fingerprint mode")
            sys.exit(1)
        fv = fingerprint_elf(args.binary)

        print(f"\n{'─'*60}")
        print(f"  ELF Feature Vector  —  {os.path.basename(fv['binary'])}")
        print(f"{'─'*60}")
        print(f"  Architecture   : {fv['arch']} ({fv['bits']}-bit)")
        print(f"  SHA-256        : {fv['sha256'][:32]}...")
        print(f"  TLSH Hash      : {fv['tlsh_hash'] or '(python-tlsh not installed)'}")
        print(f"  Build-ID       : {fv['build_id'] or '(none)'}")
        print(f"  Symbols found  : {len(fv['exported_symbols'])}")
        if fv['exported_symbols']:
            shown = fv['exported_symbols'][:8]
            print(f"  Sample symbols : {', '.join(shown)}" +
                  (" ..." if len(fv['exported_symbols']) > 8 else ""))
        print(f"\n  Section sizes:")
        for name, size in sorted(fv['section_sizes'].items(),
                                  key=lambda x: -x[1])[:6]:
            print(f"    {name:<20} {size:>10,} bytes")
        print(f"\n  CSD Candidate:")
        if fv['candidate']:
            for k, v in fv['candidate'].items():
                print(f"    {k:<18} {v}")
        else:
            print("    (no symbols exported — binary may be stripped)")
        print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
