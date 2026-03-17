"""Tests for ubice.fingerprint.bloom."""
import io
import tempfile
import pathlib
import pytest
from ubice.fingerprint.bloom import BloomFilter


def test_add_and_contains():
    bf = BloomFilter(n_bits=8000, k_hashes=4)
    bf.add("T1A3F256")
    assert "T1A3F256" in bf


def test_not_contains():
    bf = BloomFilter(n_bits=8000, k_hashes=4)
    bf.add("T1A3F256")
    # Very likely not a false positive for a random string
    assert "XXXXXXXXNOTHERE" not in bf


def test_item_count():
    bf = BloomFilter(n_bits=80_000, k_hashes=4)
    for i in range(100):
        bf.add(f"hash-{i}")
    assert bf.item_count == 100


def test_optimal_constructor():
    bf = BloomFilter.optimal(expected_items=1000, fpr=0.01)
    assert bf._n > 0
    assert bf._k >= 1


def test_save_and_load(tmp_path):
    bf = BloomFilter(n_bits=8000, k_hashes=4)
    bf.add("hello")
    bf.add("world")
    path = tmp_path / "test.bloom"
    bf.save(path)

    bf2 = BloomFilter.load(path)
    assert "hello" in bf2
    assert "world" in bf2
    assert "nothere12345" not in bf2
    assert bf2.item_count == 2


def test_estimated_fpr_zero_items():
    bf = BloomFilter(n_bits=80_000, k_hashes=7)
    assert bf.estimated_fpr == 0.0
