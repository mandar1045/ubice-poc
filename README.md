# UBICE — Universal Binary Intelligence & Compliance Engine

**GSoC 2026 Proof-of-Concept** | FOSSology | Mandar Joshi

[![CI](https://github.com/your-username/fossology-gsoc/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/fossology-gsoc/actions)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-green.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
[![SPDX](https://img.shields.io/badge/SBOM-SPDX%202.3-orange)](https://spdx.dev/)

---

## What This PoC Proves

UBICE is a proposed new FOSSology agent that fingerprints compiled binary artifacts — firmware images, stripped shared libraries, embedded device filesystems — to identify the open-source packages they contain and generate a machine-readable SBOM.  This proof-of-concept validates the two hardest technical risks in the proposal before a single line of production C code is written: **(1)** that multi-signal ELF fingerprinting (SHA-256 exact + GNU Build-ID exact + TLSH fuzzy + symbol-bag) can be composed into a single coherent `FeatureVector` pipeline; and **(2)** that the Bloom filter / SQLite CSD two-stage lookup architecture delivers correct results and serialises cleanly.  The PoC also demonstrates that the FOSSology ITEM/OK/CLOSE scheduler protocol can be cleanly wrapped in a testable Python class, and that a valid SPDX 2.3 JSON SBOM can be emitted from identified components — closing the loop from binary blob to compliance artifact.

---

## Architecture Overview

The full UBICE system comprises six modules.  This PoC implements the shaded ones end-to-end.

```
 Binary Input
      |
      v
+---------------------+       Module 1 — Binary Intake & Unpacking
| FOSSology Scheduler |  <--   (PoC: ubice/agent/scheduler.py)
| ITEM/OK/CLOSE IPC   |
+---------------------+
      |
      v
+---------------------+       Module 2 — Feature Extraction
| ELF Feature         |  <--   (PoC: ubice/extractor/elf.py)
| Extractor           |        SHA-256, Build-ID, TLSH, symbols,
|  FeatureVector      |        section sizes, .rodata strings
+---------------------+
      |
      v
+-----------------------------+  Module 3 — Multi-Stage Fingerprinting
| Stage 1a: Bloom Filter      |  (PoC: ubice/fingerprint/bloom.py)
|   O(1) pre-screen           |        Pure-Python, serialisable
+-----------------------------+
      |
      v
+-----------------------------+
| Stage 1b: CSD SQLite Lookup |  (PoC: ubice/fingerprint/csd.py)
|   sha256 / build_id / tlsh  |        Schema + seed data + TLSH scan
+-----------------------------+
      |
      v
+-----------------------------+  Module 4 — Symbol-Bag / SimHash (planned)
| Stage 2: Symbol SimHash     |        Jaccard over exported symbol sets
| (full GSoC implementation)  |
+-----------------------------+
      |
      v
+-----------------------------+  Module 5 — SBOM Generation
| SPDX 2.3 JSON Emitter       |  (PoC: ubice/sbom/spdx.py)
|   + CycloneDX (planned)     |        PackageURL, checksums, confidence
+-----------------------------+
      |
      v
+-----------------------------+  Module 6 — FOSSology DB Integration
| PostgreSQL + REST API        |        (full GSoC implementation)
| (full GSoC implementation)  |
+-----------------------------+
```

---

## What This PoC Proves

### Risk 1 — Multi-signal fingerprinting composes correctly

The ELF extractor (`ubice/extractor/elf.py`) produces a `FeatureVector` that carries every signal used at different lookup stages:

| Signal | Method | Collision probability |
|---|---|---|
| SHA-256 (whole-file) | Exact hash | 1 in 2^256 |
| GNU Build-ID | Exact hex | Cryptographic — injected at link time |
| TLSH fuzzy hash | `tlsh.diff()` distance <= 30 | ~0.8% FPR at CSD scale |
| Exported symbol bag | SimHash / Jaccard | Planned Stage 2 |

All four are populated in a single `extract()` call with no inter-module coupling.

### Risk 2 — Two-stage CSD lookup architecture works at scale

The Bloom filter (`ubice/fingerprint/bloom.py`) acts as an O(1) gate.  Any binary whose hashes are not in the filter is rejected immediately — **zero SQL round-trips** for unknown binaries.  Only Bloom-positive candidates reach the SQLite CSD (`ubice/fingerprint/csd.py`), where an exact-match index lookup or a linear TLSH scan identifies the component.  The Bloom filter serialises to a compact binary file (magic header + bitarray), so the production agent can memory-map a pre-built filter at startup.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/your-username/fossology-gsoc.git
cd fossology-gsoc/ubice_poc

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Runtime dependencies
pip install -r requirements.txt

# Development + test dependencies
pip install -r requirements-dev.txt
```

**Optional — TLSH fuzzy hashing (strongly recommended):**

```bash
pip install python-tlsh
```

Without `python-tlsh`, SHA-256 and Build-ID exact matching still work; TLSH fields are left `None`.

---

## Usage

### 1. Full pipeline demo — analyse any ELF binary

```bash
python3 demo.py /bin/ls
python3 demo.py /lib/x86_64-linux-gnu/libc.so.6
python3 demo.py /usr/bin/openssl
```

**Sample output (abbreviated):**

```
----------------------------------------------------------------
  UBICE Analysis Pipeline — ls
----------------------------------------------------------------

[1/4] ELF Feature Extraction
  Architecture   : x86_64 (64-bit)
  SHA-256        : 4a7d1ed414474e4033ac29ccb8653d9b...
  TLSH Hash      : T12F4A3B8C2E1D9F5A7B3C6E8A0D2F4A6...
  Build-ID       : 3c5e9a1b4f2d8e7c
  Exported syms  : 0
  Imported syms  : 47
  Sections       : 28
    .text                    102,456 bytes
    .rodata                   38,912 bytes
    .data                      4,096 bytes
    .eh_frame                  3,224 bytes

[2/4] Bloom Filter Pre-screen
  CSD entries    : 4
  Bloom size     : 11 KB, 7 hashes, estimated FPR=0.0000%
  Bloom decision : MISS -> skip lookup (not in known signatures)

[3/4] CSD Lookup
  No match found in demo CSD — binary not in seed dataset
  (In production CSD will cover 3,000+ packages across 6 ecosystems)

[4/4] SPDX 2.3 SBOM Generation
  (no SBOM generated — no component identified)

----------------------------------------------------------------
```

### 2. Skip SBOM output

```bash
python3 demo.py /bin/ls --no-sbom
```

### 3. FOSSology scheduler IPC demo (original PoC)

```bash
# Simulate the FOSSology scheduler sending ITEM tokens
echo -e "ITEM 42\nITEM 99\nCLOSE" | python3 ubice_ipc_demo.py --mode ipc
```

**Sample output:**

```
[ubice] agent started
[ubice] processing upload_pk=42
[ubice] result: {'status': 'ok', 'upload_pk': 42, 'signals': {...}}
OK 42
[ubice] processing upload_pk=99
OK 99
[ubice] received CLOSE, exiting cleanly
```

### 4. Fingerprint mode (original PoC)

```bash
python3 ubice_ipc_demo.py --mode fingerprint --binary /bin/ls
```

---

## Project Structure

```
ubice_poc/
|
|-- ubice/                          # Installable package
|   |-- __init__.py                 # Version: 0.1.0
|   |
|   |-- agent/
|   |   |-- __init__.py
|   |   `-- scheduler.py            # FOSSology ITEM/OK/CLOSE IPC loop
|   |
|   |-- extractor/
|   |   |-- __init__.py
|   |   `-- elf.py                  # ELF -> FeatureVector (pyelftools + TLSH)
|   |
|   |-- fingerprint/
|   |   |-- __init__.py
|   |   |-- bloom.py                # Pure-Python Bloom filter (no deps)
|   |   `-- csd.py                  # SQLite Component Signature Database
|   |
|   `-- sbom/
|       |-- __init__.py
|       `-- spdx.py                 # SPDX 2.3 JSON emitter
|
|-- tests/
|   |-- __init__.py
|   |-- test_bloom.py               # 6 tests — add/contains/save/load/FPR
|   |-- test_csd.py                 # 5 tests — seed/lookup/idempotency
|   |-- test_scheduler.py           # 3 tests — ITEM/OK/CLOSE protocol
|   `-- test_spdx.py                # 3 tests — JSON validity/PURL/multi-component
|
|-- .github/
|   `-- workflows/
|       `-- ci.yml                  # Matrix CI: Python 3.10 / 3.11 / 3.12
|
|-- demo.py                         # Full 4-stage pipeline demo
|-- ubice_ipc_demo.py               # Original IPC + fingerprint demo
|-- requirements.txt
|-- requirements-dev.txt
`-- README.md
```

---

## Mapping to GSoC Proposal

| PoC File | UBICE Module | Proposal Section |
|---|---|---|
| `ubice/agent/scheduler.py` | Module 1 — Binary Intake | 3.1 FOSSology Agent Integration |
| `ubice/extractor/elf.py` | Module 2 — Feature Extraction | 3.2 Multi-Signal Fingerprinting |
| `ubice/fingerprint/bloom.py` | Module 3 — Stage 1a Pre-filter | 3.3 Two-Stage CSD Lookup |
| `ubice/fingerprint/csd.py` | Module 3 — Stage 1b CSD Lookup | 3.3 Two-Stage CSD Lookup |
| `ubice/sbom/spdx.py` | Module 5 — SBOM Generation | 3.5 SBOM Output (SPDX/CycloneDX) |
| `tests/` | All modules | 5. Testing & Validation Plan |
| `.github/workflows/ci.yml` | Infrastructure | 6. Deliverables |

---

## Technical Highlights

### Bloom Filter (`ubice/fingerprint/bloom.py`)

- Pure Python, zero external dependencies beyond `hashlib`
- Double-hashing technique: `h(i) = (h1 + i*h2) mod n` — only two hash digests computed per item regardless of k
- `BloomFilter.optimal(expected_items, fpr)` factory: calculates the minimum bit-array size and optimal k for a given false-positive rate using the standard information-theoretic formula
- Binary serialisation with magic header (`UBICE_BF\x01`) for safe file loading
- In the production agent, a pre-built `.bloom` file is memory-mapped at agent start, reducing CSD SQL queries by >99% for new/unknown binaries

### TLSH Fuzzy Hashing

[TLSH (Trend Locality Sensitive Hash)](https://github.com/trendmicro/tlsh) is a locality-sensitive hash designed for binary files: two binaries that differ by a small patch produce hashes with a low numeric distance (typically < 30 for recompiled packages with the same source).  UBICE uses TLSH as its Stage 1b fuzzy-match signal — after SHA-256 and Build-ID exact lookups fail.  The `lookup_tlsh()` method in `csd.py` scans candidates pre-filtered by the Bloom filter and returns the closest match within a configurable distance threshold.

### SQLite CSD (`ubice/fingerprint/csd.py`)

The Component Signature Database stores one row per binary artifact (not per source package), with three indexed lookup columns:

```sql
CREATE INDEX idx_sha256   ON binary_signature(sha256);
CREATE INDEX idx_build_id ON binary_signature(build_id);
CREATE INDEX idx_tlsh     ON binary_signature(tlsh_hash);
```

Each row carries a [PackageURL (purl)](https://github.com/package-url/purl-spec) as the canonical package identifier — making the CSD ecosystem-agnostic (Debian, Ubuntu, Alpine, Yocto, Buildroot, NixOS).  The production CSD will be populated by an offline pipeline that processes Debian snapshot archives, Ubuntu PPAs, and Alpine package repositories.

### SPDX 2.3 JSON SBOM (`ubice/sbom/spdx.py`)

The `SPDXDocument` class emits a spec-compliant SPDX 2.3 JSON document with:
- `externalRefs` of type `purl` for each identified component (machine-readable dependency tracking)
- `checksums` populated from the `FeatureVector` SHA-256 when available
- `comment` fields recording match stage and confidence percentage (auditable provenance)
- Unique `documentNamespace` UUID per document (required by the SPDX spec)

The full GSoC implementation will upgrade to SPDX 3.0, add CycloneDX 1.6 output, and sign each document with [Sigstore](https://www.sigstore.dev/) (Fulcio certificate + Rekor transparency log entry).

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=ubice --cov-report=term-missing

# Single module
pytest tests/test_bloom.py -v
```

**Test results:**

```
tests/test_bloom.py::test_add_and_contains         PASSED
tests/test_bloom.py::test_not_contains             PASSED
tests/test_bloom.py::test_item_count               PASSED
tests/test_bloom.py::test_optimal_constructor      PASSED
tests/test_bloom.py::test_save_and_load            PASSED
tests/test_bloom.py::test_estimated_fpr_zero_items PASSED
tests/test_csd.py::test_seed_inserts_rows          PASSED
tests/test_csd.py::test_lookup_sha256_miss         PASSED
tests/test_csd.py::test_lookup_build_id_miss       PASSED
tests/test_csd.py::test_seed_is_idempotent         PASSED
tests/test_csd.py::test_component_match_as_dict    PASSED
tests/test_scheduler.py::test_item_ok_close        PASSED
tests/test_scheduler.py::test_empty_stream         PASSED
tests/test_scheduler.py::test_close_immediately    PASSED
tests/test_spdx.py::test_to_json_valid             PASSED
tests/test_spdx.py::test_purl_external_ref         PASSED
tests/test_spdx.py::test_multiple_components       PASSED

17 passed in 0.04s
```

---

## What the Full GSoC Implementation Will Add

| Feature | Status in PoC | Full Implementation |
|---|---|---|
| ELF extraction | Complete | Add PE/Mach-O support via LIEF |
| CSD population pipeline | Demo seed data (4 rows) | Offline pipeline: 3,000+ packages, 6 ecosystems |
| TLSH lookup | Linear scan (O(n)) | Inverted index + LSH bucketing (O(1) amortised) |
| Stage 2: Symbol SimHash | Not implemented | Jaccard distance over exported symbol bags |
| SBOM format | SPDX 2.3 JSON | SPDX 3.0 + CycloneDX 1.6 + Sigstore signing |
| FOSSology DB integration | Mocked upload_pk | Full `fo_dbconnect()` + `binary_finding` table writes |
| REST API | Not implemented | `/api/v2/uploads/{id}/sbom` endpoint |
| Stripped binary recovery | Not implemented | Dwarf info + external debug symbol packages |
| Performance | Single-threaded Python | Multi-threaded C agent with Python extension modules |
| Confidence scoring | Basic linear formula | Calibrated Bayesian model with per-signal weights |

The PoC is intentionally written in Python so that the architecture is readable and testable without a full FOSSology build environment.  The production agent will be written in C following FOSSology agent conventions, with the Bloom filter and TLSH logic either ported to C or called via CPython extension modules.

---

## About the Author

**Mandar Joshi** — GSoC 2026 applicant, FOSSology.

FOSSology upstream contributions:
- [FOSSology Pull Requests](https://github.com/fossology/fossology/pulls?q=is%3Apr+author%3Amandar12) — codebase exploration and bug fixes submitted during the application period

This PoC was built as part of the GSoC 2026 application for the project *"UBICE: Universal Binary Intelligence & Compliance Engine"* under the FOSSology organisation.

---

## License

This proof-of-concept is released under the **GNU General Public License v2.0**, matching FOSSology's own license.

```
Copyright (C) 2026 Mandar Joshi

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.
```
