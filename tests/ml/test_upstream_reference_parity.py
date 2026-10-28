"""
Controlled Independent Upstream EMBER v2 Reference Parity Test Suite.

Milestone: ML-08A & ML-08B
Verifies feature extraction parity of app/ml/ember_v2.py against the genuine,
independent upstream Elastic EMBER reference implementation located in
vendor/elastic_ember_upstream at pinned commit d97a0b523de02f3fe5ea6089d080abacab6ee931.
Includes extended offline validation matrix across PE32/PE32+, formats, section
counts, real host PE binaries/DLLs, malformed inputs, and repeatability.
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
        vendor_features_path = Path(__file__).resolve().parents[2] / "vendor" / "elastic_ember_upstream" / "ember" / "features.py"
        if not vendor_features_path.exists():
            raise unittest.SkipTest(f"Upstream vendor features.py not found at: {vendor_features_path}")
        cls.upstream_extractor = load_upstream_extractor()
        cls.local_extractor = EMBERFeatureExtractor(print_warning=False)

    def _assert_fixture_parity(self, bytez: bytes, fixture_name: str):
        v_up = self.upstream_extractor.feature_vector(bytez)
        v_loc = self.local_extractor.feature_vector(bytez)

        self.assertEqual(len(v_up), EMBER_V2_TOTAL_DIM)
        self.assertEqual(len(v_loc), EMBER_V2_TOTAL_DIM)
        self.assertEqual(v_loc.dtype, np.float32)
        self.assertTrue(np.all(np.isfinite(v_up)))
        self.assertTrue(np.all(np.isfinite(v_loc)))

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

    # --- Core ML-08A Baseline Fixtures ---

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

    # --- Extended Synthetic Coverage (PE32/PE32+, Subsystems, Section Counts) ---

    def test_pe_ext_01_synthetic_x86_gui(self):
        """Verify parity on synthetic 32-bit GUI executable."""
        bytez = build_synthetic_pe(is_64bit=False, is_dll=False, is_driver=False, subsystem=2)
        self._assert_fixture_parity(bytez, "PE-EXT-01 (Synthetic x86 GUI)")

    def test_pe_ext_02_synthetic_x86_dll(self):
        """Verify parity on synthetic 32-bit DLL."""
        bytez = build_synthetic_pe(is_64bit=False, is_dll=True, is_driver=False)
        self._assert_fixture_parity(bytez, "PE-EXT-02 (Synthetic x86 DLL)")

    def test_pe_ext_03_synthetic_x86_driver(self):
        """Verify parity on synthetic 32-bit Kernel Driver."""
        bytez = build_synthetic_pe(is_64bit=False, is_dll=False, is_driver=True)
        self._assert_fixture_parity(bytez, "PE-EXT-03 (Synthetic x86 Driver)")

    def test_pe_ext_04_synthetic_x64_cui(self):
        """Verify parity on synthetic 64-bit Console executable."""
        bytez = build_synthetic_pe(is_64bit=True, is_dll=False, is_driver=False, subsystem=3)
        self._assert_fixture_parity(bytez, "PE-EXT-04 (Synthetic x64 CUI)")

    def test_pe_ext_05_synthetic_x64_single_section(self):
        """Verify parity on synthetic 64-bit executable with single section."""
        bytez = build_synthetic_pe(is_64bit=True, num_sections=1)
        self._assert_fixture_parity(bytez, "PE-EXT-05 (Synthetic x64 1-Section)")

    # --- Extended Real Host Binaries & DLL Extensions ---

    def test_pe_real_01_host_pythonw_gui(self):
        """Verify parity on real GUI host binary (pythonw.exe)."""
        exe_path = Path(sys.executable).parent / "pythonw.exe"
        if not exe_path.exists():
            self.skipTest("pythonw.exe not found in environment")
        bytez = exe_path.read_bytes()
        self._assert_fixture_parity(bytez, "PE-REAL-01 (Host pythonw.exe)")

    def test_pe_real_02_host_pip_launcher(self):
        """Verify parity on real CLI launcher binary (pip.exe)."""
        exe_path = Path(sys.executable).parent / "pip.exe"
        if not exe_path.exists():
            self.skipTest("pip.exe not found in environment")
        bytez = exe_path.read_bytes()
        self._assert_fixture_parity(bytez, "PE-REAL-02 (Host pip.exe)")

    def test_pe_real_03_dll_speedups(self):
        """Verify parity on real compiled C-extension DLL (_speedups.pyd)."""
        pyd_path = Path(__file__).resolve().parents[2] / "venv" / "Lib" / "site-packages" / "markupsafe" / "_speedups.cp314-win_amd64.pyd"
        if not pyd_path.exists():
            self.skipTest(f"{pyd_path.name} not found in environment")
        bytez = pyd_path.read_bytes()
        self._assert_fixture_parity(bytez, "PE-REAL-03 (_speedups.pyd)")

    def test_pe_real_04_dll_url_parser(self):
        """Verify parity on real compiled C-extension DLL (url_parser.pyd)."""
        pyd_path = Path(__file__).resolve().parents[2] / "venv" / "Lib" / "site-packages" / "httptools" / "parser" / "url_parser.cp314-win_amd64.pyd"
        if not pyd_path.exists():
            self.skipTest(f"{pyd_path.name} not found in environment")
        bytez = pyd_path.read_bytes()
        self._assert_fixture_parity(bytez, "PE-REAL-04 (url_parser.pyd)")

    def test_pe_real_05_dll_yara(self):
        """Verify parity on real compiled C-extension DLL (yara.pyd)."""
        pyd_path = Path(__file__).resolve().parents[2] / "venv" / "Lib" / "site-packages" / "yara.cp314-win_amd64.pyd"
        if not pyd_path.exists():
            self.skipTest(f"{pyd_path.name} not found in environment")
        bytez = pyd_path.read_bytes()
        self._assert_fixture_parity(bytez, "PE-REAL-05 (yara.pyd)")

    # --- Boundary Cases, Parser Failures & Determinism ---

    def test_malformed_empty_payload_safe_handling(self):
        """Verify that empty payload produces finite zeros in local extractor without unhandled crash."""
        v_loc = self.local_extractor.feature_vector(b"")
        self.assertEqual(len(v_loc), EMBER_V2_TOTAL_DIM)
        self.assertEqual(v_loc.dtype, np.float32)
        self.assertTrue(np.all(np.isfinite(v_loc)))
        self.assertTrue(np.all(v_loc == 0.0))

    def test_malformed_truncated_dos_header(self):
        """Verify safe handling and 2,377/2,381 feature parity on truncated DOS header."""
        sample = b"MZ\x00\x01\x02\x03"
        v_up = self.upstream_extractor.feature_vector(sample)
        v_loc = self.local_extractor.feature_vector(sample)

        self.assertEqual(len(v_loc), EMBER_V2_TOTAL_DIM)
        self.assertTrue(np.all(np.isfinite(v_loc)))
        # 2,377 features match exactly; 4 differ due to upstream empty-string hashing vs local zeroing
        diff = np.abs(v_up - v_loc)
        exact = int(np.sum(diff == 0.0))
        self.assertEqual(exact, 2377)

    def test_malformed_truncated_coff_header(self):
        """Verify safe handling and 2,377/2,381 feature parity on truncated COFF header."""
        sample = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00\x64\x86\x01\x00"
        v_up = self.upstream_extractor.feature_vector(sample)
        v_loc = self.local_extractor.feature_vector(sample)

        self.assertEqual(len(v_loc), EMBER_V2_TOTAL_DIM)
        self.assertTrue(np.all(np.isfinite(v_loc)))
        diff = np.abs(v_up - v_loc)
        exact = int(np.sum(diff == 0.0))
        self.assertEqual(exact, 2377)

    def test_malformed_non_pe_garbage(self):
        """Verify safe handling and 2,377/2,381 feature parity on non-PE arbitrary payload."""
        sample = b"\x42" * 1024
        v_up = self.upstream_extractor.feature_vector(sample)
        v_loc = self.local_extractor.feature_vector(sample)

        self.assertEqual(len(v_loc), EMBER_V2_TOTAL_DIM)
        self.assertTrue(np.all(np.isfinite(v_loc)))
        diff = np.abs(v_up - v_loc)
        exact = int(np.sum(diff == 0.0))
        self.assertEqual(exact, 2377)

    def test_repeatability_and_determinism(self):
        """Verify repeatability: repeated extractions produce 100% bitwise identical vectors."""
        test_samples = [
            build_synthetic_pe(is_64bit=True),
            build_synthetic_pe(is_64bit=False, subsystem=3),
            Path(sys.executable).read_bytes(),
            b"MZ\x00\x01\x02\x03",
        ]
        for s in test_samples:
            v1 = self.local_extractor.feature_vector(s)
            v2 = self.local_extractor.feature_vector(s)
            self.assertTrue(np.array_equal(v1, v2))


if __name__ == "__main__":
    unittest.main()
