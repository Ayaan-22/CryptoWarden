"""
Unit tests for the CryptoWarden Entropy Calculator.
Validates Shannon entropy computation across various data patterns.
"""
import sys
import os
import tempfile
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from src.analysis.entropy import calculate_shannon_entropy, calculate_file_entropy


class TestShannonEntropy:
    """Tests for the core entropy calculation algorithm."""

    def test_empty_data_returns_zero(self):
        assert calculate_shannon_entropy(b'') == 0.0

    def test_single_byte_returns_zero(self):
        """A single byte has no uncertainty."""
        assert calculate_shannon_entropy(b'\x00') == 0.0

    def test_uniform_data_returns_zero(self):
        """All identical bytes = no randomness."""
        data = b'\xAA' * 1024
        assert calculate_shannon_entropy(data) == 0.0

    def test_two_equal_values_returns_one(self):
        """50/50 split of two values = 1.0 bit of entropy."""
        data = b'\x00\x01' * 512
        entropy = calculate_shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_random_data_has_high_entropy(self):
        """Random-looking data should have entropy close to 8.0."""
        # Create data with all 256 byte values equally distributed
        data = bytes(range(256)) * 4
        entropy = calculate_shannon_entropy(data)
        assert entropy > 7.9

    def test_english_text_has_moderate_entropy(self):
        """Normal English text typically has entropy ~4.0-5.0."""
        text = b"The quick brown fox jumps over the lazy dog. " * 20
        entropy = calculate_shannon_entropy(text)
        assert 3.5 < entropy < 5.5

    def test_entropy_bounded_0_to_8(self):
        """Entropy of byte data is always between 0.0 and 8.0."""
        import random
        for _ in range(10):
            data = bytes(random.randint(0, 255) for _ in range(1000))
            entropy = calculate_shannon_entropy(data)
            assert 0.0 <= entropy <= 8.0

    def test_structured_binary_has_low_entropy(self):
        """Repetitive structured data (e.g., CSV of zeros) has low entropy."""
        data = b"0,0,0,0,0,0\n" * 100
        entropy = calculate_shannon_entropy(data)
        assert entropy < 3.0


class TestFileEntropy:
    """Tests for file-based entropy calculation."""

    def test_small_text_file(self):
        """Small text file should have moderate entropy."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"Hello World! This is a test file for entropy." * 10)
            path = f.name
        try:
            entropy = calculate_file_entropy(path)
            assert 3.0 < entropy < 6.0
        finally:
            os.unlink(path)

    def test_random_binary_file(self):
        """File with random bytes should have high entropy (simulates encrypted data)."""
        import random
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(bytes(random.randint(0, 255) for _ in range(4096)))
            path = f.name
        try:
            entropy = calculate_file_entropy(path)
            assert entropy > 7.0
        finally:
            os.unlink(path)

    def test_empty_file_returns_zero(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            path = f.name
        try:
            entropy = calculate_file_entropy(path)
            assert entropy == 0.0
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_zero(self):
        """Missing file should return 0.0 without crashing."""
        entropy = calculate_file_entropy("/nonexistent/path/file.txt")
        assert entropy == 0.0

    def test_large_file_uses_sampling(self):
        """Files > 3072 bytes should use head+mid+tail sampling."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            # Write 10KB of structured data
            f.write(b"A" * 4096)  # Head: low entropy
            f.write(b"B" * 2048)  # Middle
            f.write(b"C" * 4096)  # Tail
            path = f.name
        try:
            entropy = calculate_file_entropy(path)
            # Should be low since it's repetitive even when sampled
            assert entropy < 3.0
        finally:
            os.unlink(path)
