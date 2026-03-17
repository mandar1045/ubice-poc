"""
ubice.extractor.elf
~~~~~~~~~~~~~~~~~~~
Extracts a FeatureVector from an ELF binary.

Corresponds to UBICE Module 2 (Feature Extraction) in the GSoC proposal.

Fields extracted:
  - Architecture + bitness
  - GNU Build-ID (strongest exact-match signal)
  - SHA-256 (whole-file exact hash)
  - TLSH fuzzy hash (tolerant of minor version differences)
  - Exported symbol names (for SimHash / symbol-bag matching)
  - Section sizes (.text, .rodata, .data, ...)
  - Import set (undefined external symbols)
  - String constants from .rodata >= 8 chars (for pattern matching)
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

__all__ = ["FeatureVector", "extract"]


@dataclass
class FeatureVector:
    """All fingerprinting signals extracted from a single ELF binary."""

    binary_path: str
    arch: Optional[str] = None
    bits: Optional[int] = None
    build_id: Optional[str] = None
    sha256: Optional[str] = None
    tlsh_hash: Optional[str] = None
    exported_symbols: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    section_sizes: dict[str, int] = field(default_factory=dict)
    rodata_strings: list[str] = field(default_factory=list)

    @property
    def symbol_count(self) -> int:
        return len(self.exported_symbols)

    def as_dict(self) -> dict:
        return {
            "binary_path": self.binary_path,
            "arch": self.arch,
            "bits": self.bits,
            "build_id": self.build_id,
            "sha256": self.sha256,
            "tlsh_hash": self.tlsh_hash,
            "exported_symbols": self.exported_symbols,
            "imported_symbols": self.imported_symbols[:20],   # truncate for readability
            "section_sizes": self.section_sizes,
            "rodata_strings_sample": self.rodata_strings[:10],
        }


def extract(binary_path: str) -> FeatureVector:
    """
    Extract a FeatureVector from *binary_path*.

    Raises FileNotFoundError, ValueError (not a valid ELF), ImportError (pyelftools missing).
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError as exc:
        raise ImportError(
            "pyelftools is required for ELF extraction. "
            "Install with: pip install pyelftools"
        ) from exc

    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"binary not found: {binary_path}")

    fv = FeatureVector(binary_path=binary_path)

    # -- whole-file hashes ---------------------------------------------------
    with open(binary_path, "rb") as fh:
        raw = fh.read()

    fv.sha256 = hashlib.sha256(raw).hexdigest()

    try:
        import tlsh as tlsh_mod
        # python-tlsh >=4.8 uses hexdigest(); older used hash()
        fn = getattr(tlsh_mod, "hexdigest", None) or getattr(tlsh_mod, "hash", None)
        h = fn(raw) if fn else None
        fv.tlsh_hash = h if h and h != "TNULL" else None
    except ImportError:
        pass  # TLSH is optional

    # -- ELF parsing ---------------------------------------------------------
    with open(binary_path, "rb") as fh:
        try:
            elf = ELFFile(fh)
        except Exception as exc:
            raise ValueError(f"not a valid ELF file: {exc}") from exc

        fv.arch = elf.get_machine_arch()
        fv.bits = elf.elfclass

        # Section sizes
        for section in elf.iter_sections():
            if section.name and section["sh_size"] > 0:
                fv.section_sizes[section.name] = section["sh_size"]

        # Symbols
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if not sym.name:
                    continue
                bind = sym.entry.st_info.bind
                shndx = sym.entry.st_shndx
                if bind in ("STB_GLOBAL", "STB_WEAK"):
                    if shndx == "SHN_UNDEF":
                        fv.imported_symbols.append(sym.name)
                    elif sym.entry.st_size > 0:
                        fv.exported_symbols.append(sym.name)

        # GNU Build-ID
        for section in elf.iter_sections():
            if section.name == ".note.gnu.build-id":
                data = section.data()
                if len(data) > 12:
                    namesz = int.from_bytes(data[0:4], "little")
                    descsz = int.from_bytes(data[4:8], "little")
                    desc_off = (12 + namesz + 3) & ~3
                    fv.build_id = data[desc_off: desc_off + descsz].hex()

        # Printable strings from .rodata
        for section in elf.iter_sections():
            if section.name == ".rodata":
                raw_rodata = section.data()
                strings = re.findall(rb"[ -~]{8,}", raw_rodata)
                fv.rodata_strings = [s.decode("ascii", errors="replace") for s in strings[:50]]

    return fv
