# UBICE Proof of Concept

GSoC 2026 — Mandar Joshi — FOSSology

This is a small working demo I built to verify the two hardest parts of the UBICE
proposal before writing the full implementation.

---

## What this demos

### 1. FOSSology Scheduler IPC (Python side)

Every FOSSology agent — nomos, monk, ojo — talks to the scheduler over
`stdin`/`stdout` using `ITEM <upload_pk>` / `OK <upload_pk>` / `CLOSE` tokens.
UBICE agents need to do the same from Python.

```bash
echo -e "ITEM 42\nITEM 99\nCLOSE" | python3 ubice_ipc_demo.py --mode ipc
```

Expected output:
```
[ubice-demo] agent started, waiting for scheduler input
[ubice-demo] processing upload_pk=42
[ubice-demo] result: {'upload_pk': 42, 'status': 'unpacked', 'files_written': 0}
OK 42
[ubice-demo] processing upload_pk=99
[ubice-demo] result: {'upload_pk': 99, 'status': 'unpacked', 'files_written': 0}
OK 99
[ubice-demo] received CLOSE, exiting cleanly
```

This is identical to what the scheduler expects from any agent. The `OK` lines
go back to the scheduler; everything else is just debug output.

---

### 2. ELF Feature Extraction + TLSH Fingerprinting

Module 2 (Feature Extraction) + Stage 1 of Module 3 (Fingerprinting).

```bash
pip install pyelftools python-tlsh
python3 ubice_ipc_demo.py --mode fingerprint --binary /bin/ls
```

Sample output (on a typical Linux system):
```
────────────────────────────────────────────────────────────
  ELF Feature Vector  —  ls
────────────────────────────────────────────────────────────
  Architecture   : x86-64 (64-bit)
  SHA-256        : 2a7d4f8c1b...
  TLSH Hash      : T1A3F2...
  Build-ID       : 8b3e9c1a... (GNU Build-ID — strongest match signal)
  Symbols found  : 47
  Sample symbols : optind, stderr, stdout, free, malloc ...

  Section sizes:
    .text                  65,432 bytes
    .rodata                12,880 bytes
    .data                   3,200 bytes
    ...

  CSD Candidate:
    note               Build-ID present — Stage 1 exact match possible
────────────────────────────────────────────────────────────
```

The TLSH hash is what gets looked up in the Bloom filter + `csd.db` during
real UBICE operation. The Build-ID (when present) lets us skip fuzzy matching
entirely and do a direct lookup.

---

## Why this matters for the proposal

The two things I was most unsure about when writing the proposal:

1. **Can Python actually speak the scheduler IPC protocol?**
   Yes — the loop is about 20 lines. `ctypes` to `libfossscheduler.so` adds
   heartbeat support for production, but stdin/stdout itself is trivial.

2. **Does TLSH actually work on real ELF binaries?**
   Yes — `python-tlsh` hashes a 100KB binary in ~2ms. TLSH distance between
   two builds of the same package version is typically < 15 (well under the
   30-threshold cutoff I specified in the proposal).

---

## Dependencies

```bash
pip install pyelftools python-tlsh
```

No FOSSology installation required to run this demo.
