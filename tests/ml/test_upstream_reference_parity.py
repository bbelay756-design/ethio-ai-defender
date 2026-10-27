"""
Controlled Independent Upstream EMBER v2 Reference Parity Test Suite.

Milestone: ML-08A
Verifies feature extraction parity of app/ml/ember_v2.py against the genuine,
independent upstream Elastic EMBER reference implementation located in
vendor/elastic_ember_upstream at pinned commit d97a0b523de02f3fe5ea6089d080abacab6ee931.
"""

import hashlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

import numpy as np
import lief
from sklearn.feature_extraction import FeatureHasher

from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM
from tests.test_pe_analyzer import build_synthetic_pe
from tests.ml.test_feature_parity import GROUP_OFFSETS

# In-memory runtime shims to execute historical 2018 upstream code on modern Python 3.14 / NumPy 2
if not hasattr(np, "int"):
    np.int = int
if not hasattr(np, "float"):
    np.float = float

if not hasattr(lief, "bad_format"):
    lief.bad_format = getattr(lief.lief_errors, "file_format_error", RuntimeError)
if not hasattr(lief, "bad_file"):
    lief.bad_file = getattr(lief.lief_errors, "file_error", RuntimeError)
if not hasattr(lief, "pe_error"):
    lief.pe_error = getattr(lief.lief_errors, "runtime_error", RuntimeError)
if not hasattr(lief, "parser_error"):
    lief.parser_error = getattr(lief.lief_errors, "parsing_error", RuntimeError)
if not hasattr(lief, "read_out_of_bound"):
    lief.read_out_of_bound = getattr(lief.lief_errors, "read_out_of_bound", RuntimeError)

_orig_transform = FeatureHasher.transform


def _compat_transform(self, raw_X):
    # Support scikit-learn 1.x requirement where samples must be iterable over iterables of strings
    if isinstance(raw_X, (list, tuple)) and len(raw_X) > 0 and isinstance(raw_X[0], str):
        raw_X = [[x] for x in raw_X]
    return _orig_transform(self, raw_X)


FeatureHasher.transform = _compat_transform


def load_upstream_extractor():
    """Load the upstream PEFeatureExtractor directly from vendor without package installation."""
    vendor_features_path = Path(__file__).resolve().parents[2] / "vendor" / "elastic_ember_upstream" / "ember" / "features.py"
    if not vendor_features_path.exists():
        raise FileNotFoundError(f"Upstream vendor features.py not found at: {vendor_features_path}")

    spec = importlib.util.spec_from_file_location("upstream_ember_features", vendor_features_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PEFeatureExtractor(feature_version=2)


class TestUpstreamReferenceParity(unittest.TestCase):
    """Test suite validating parity against the official upstream Elastic EMBER reference."""

    @classmethod
    def setUpClass(cls):
        cls.upstream_extractor = load_upstream_extractor()
        cls.local_extractor = EMBERFeatureExtractor(print_warning=False)

    def _assert_fixture_parity(self, bytez: bytes, fixture_name: str):
        v_up = self.upstream_extractor.feature_vector(bytez)
        v_loc = self.local_extractor.feature_vector(bytez)

        self.assertEqual(len(v_up), EMBER_V2_TOTAL_DIM)
        self.assertEqual(len(v_loc), EMBER_V2_TOTAL_DIM)

        diff = np.abs(v_up - v_loc)
        mismatches = int(np.sum(diff > 1e-5))
        max_error = float(np.max(diff))

        self.assertEqual(
            mismatches, 0,
            f"Fixture '{fixture_name}' had {mismatches} mismatches exceeding 1e-5 tolerance! Max diff: {max_error}"
        )
        self.assertLess(max_error, 1e-5, f"Fixture '{fixture_name}' max error {max_error} exceeds 1e-5")

        # Per-group validation
        for gname, (start, end) in GROUP_OFFSETS.items():
            g_diff = diff[start:end]
            g_mismatches = int(np.sum(g_diff > 1e-5))
            self.assertEqual(
                g_mismatches, 0,
                f"Feature group '{gname}' in fixture '{fixture_name}' had {g_mismatches} mismatches!"
            )

    def test_pe_fix_01_synthetic_x64_gui(self):
        """Verify parity against upstream on synthetic 64-bit GUI executable."""
        bytez = build_synthetic_pe(is_64bit=True, is_dll=False, is_driver=False)
        self._assert_fixture_parity(bytez, "PE-FIX-01 (Synthetic x64 GUI)")

    def test_pe_fix_02_synthetic_x86_cui(self):
        """Verify parity against upstream on synthetic 32-bit Console executable."""
        bytez = build_synthetic_pe(is_64bit=False, is_dll=False, is_driver=False, subsystem=3)
        self._assert_fixture_parity(bytez, "PE-FIX-02 (Synthetic x86 CUI)")

    def test_pe_fix_03_synthetic_dll(self):
        """Verify parity against upstream on synthetic 64-bit DLL."""
        bytez = build_synthetic_pe(is_64bit=True, is_dll=True, is_driver=False)
        self._assert_fixture_parity(bytez, "PE-FIX-03 (Synthetic DLL)")

    def test_pe_fix_04_synthetic_driver(self):
        """Verify parity against upstream on synthetic Kernel Driver."""
        bytez = build_synthetic_pe(is_64bit=True, is_dll=False, is_driver=True)
        self._assert_fixture_parity(bytez, "PE-FIX-04 (Synthetic Driver)")

    def test_pe_fix_05_host_python_binary(self):
        """Verify parity against upstream on real host Windows PE binary."""
        exe_path = Path(sys.executable)
        self.assertTrue(exe_path.exists())
        bytez = exe_path.read_bytes()
        self._assert_fixture_parity(bytez, "PE-FIX-05 (Host python.exe)")


if __name__ == "__main__":
    unittest.main()
