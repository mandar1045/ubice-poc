"""
ubice.fingerprint.bloom
~~~~~~~~~~~~~~~~~~~~~~~
Pure-Python Bloom filter using SHA-256 with k different seeds.
Used as the O(1) pre-filter before the SQLite CSD lookup.

FPR at default settings (8 MB, 7 hashes, 1M items) approximately 0.8%.

Usage::

    bf = BloomFilter.new()
    bf.add("T1A3F2...")   # TLSH hash string
    assert "T1A3F2..." in bf

    bf.save("csd.bloom")
    bf2 = BloomFilter.load("csd.bloom")
"""
from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path

__all__ = ["BloomFilter"]

_MAGIC = b"UBICE_BF\x01"


class BloomFilter:
    """
    A serialisable Bloom filter backed by a Python bytearray.

    Parameters
    ----------
    n_bits:    total number of bits (must be divisible by 8)
    k_hashes:  number of independent hash functions
    """

    def __init__(self, n_bits: int = 8_000_000, k_hashes: int = 7) -> None:
        if n_bits % 8:
            raise ValueError("n_bits must be divisible by 8")
        self._n = n_bits
        self._k = k_hashes
        self._bits = bytearray(n_bits // 8)
        self._count = 0

    # -- public API ----------------------------------------------------------

    @classmethod
    def optimal(cls, expected_items: int, fpr: float = 0.01) -> "BloomFilter":
        """Create a Bloom filter sized for *expected_items* at *fpr* false-positive rate."""
        n = math.ceil(-expected_items * math.log(fpr) / (math.log(2) ** 2))
        n = ((n + 7) // 8) * 8       # round up to byte boundary
        k = max(1, round((n / expected_items) * math.log(2)))
        return cls(n_bits=n, k_hashes=k)

    def add(self, item: str) -> None:
        """Add *item* (string) to the filter."""
        for bit_idx in self._hashes(item):
            byte_idx, bit_pos = divmod(bit_idx, 8)
            self._bits[byte_idx] |= 1 << bit_pos
        self._count += 1

    def __contains__(self, item: str) -> bool:
        """Return True if *item* is *probably* in the filter."""
        return all(
            self._bits[byte_idx] & (1 << bit_pos)
            for bit_idx in self._hashes(item)
            for byte_idx, bit_pos in [divmod(bit_idx, 8)]
        )

    @property
    def item_count(self) -> int:
        return self._count

    @property
    def estimated_fpr(self) -> float:
        if self._count == 0:
            return 0.0
        p_bit_not_set = (1 - 1 / self._n) ** (self._k * self._count)
        return (1 - p_bit_not_set) ** self._k

    # -- persistence ---------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Serialise to *path*."""
        header = struct.pack(">9sII", _MAGIC, self._n, self._k)
        count_bytes = struct.pack(">Q", self._count)
        with open(path, "wb") as fh:
            fh.write(header)
            fh.write(count_bytes)
            fh.write(self._bits)

    @classmethod
    def load(cls, path: str | Path) -> "BloomFilter":
        """Deserialise from *path*."""
        with open(path, "rb") as fh:
            header = fh.read(17 + 8)   # magic(9)+n(4)+k(4) + count(8)
            magic, n_bits, k_hashes = struct.unpack(">9sII", header[:17])
            if magic != _MAGIC:
                raise ValueError("not a UBICE Bloom filter file")
            count = struct.unpack(">Q", header[17:25])[0]
            bits = bytearray(fh.read())
        bf = cls(n_bits=n_bits, k_hashes=k_hashes)
        bf._bits = bits
        bf._count = count
        return bf

    # -- internal ------------------------------------------------------------

    def _hashes(self, item: str) -> list[int]:
        """Produce k bit positions for *item* using double-hashing technique."""
        encoded = item.encode()
        h1 = int(hashlib.sha256(encoded).hexdigest(), 16) % self._n
        h2 = int(hashlib.md5(encoded).hexdigest(), 16) % self._n
        return [(h1 + i * h2) % self._n for i in range(self._k)]
