"""
EMBER v2 Feature Extractor for ETHIO-AI Defender

Implements the official EMBER v2 feature extraction (2,381 dimensions)
compatible with elastic/ember reference implementation.

Reference: https://github.com/elastic/ember/blob/master/ember/features.py
Feature Version: 2
LIEF Version: 1.0.0 (compatible with reference 0.9.0)
"""

import re
import hashlib
import numpy as np
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from sklearn.feature_extraction import FeatureHasher

try:
    import lief
except ImportError:
    lief = None


# LIEF version compatibility
LIEF_VERSION = "0.0.0"
LIEF_MAJOR = 0
LIEF_MINOR = 0
LIEF_PATCH = 0
if lief is not None:
    LIEF_VERSION = lief.__version__
    try:
        parts = LIEF_VERSION.split('.')
        LIEF_MAJOR = int(parts[0]) if len(parts) > 0 else 0
        LIEF_MINOR = int(parts[1]) if len(parts) > 1 else 0
        LIEF_PATCH = int(parts[2].split('-')[0]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        pass

# Feature version 2 includes DataDirectories (requires LIEF 0.9.0+)
LIEF_HAS_DATA_DIRECTORIES = LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 9)
LIEF_HAS_SIGNATURE = LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 11)
LIEF_HAS_EXPORT_OBJECT = LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 10)
LIEF_HAS_SECTION_FROM_RVA = LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 12)


@dataclass
class FeatureGroup:
    """Metadata for a feature group."""
    name: str
    dim: int
    description: str


# EMBER v2 Feature Contract - Ordered Feature Groups
EMBER_V2_FEATURE_GROUPS: List[FeatureGroup] = [
    FeatureGroup("histogram", 256, "Normalized byte frequency histogram"),
    FeatureGroup("byteentropy", 256, "2D byte/entropy joint histogram (16x16)"),
    FeatureGroup("strings", 104, "String statistics and printable character distribution"),
    FeatureGroup("general", 10, "Basic file metadata and PE properties"),
    FeatureGroup("header", 62, "COFF and Optional header fields"),
    FeatureGroup("section", 255, "Section metadata with feature hashing"),
    FeatureGroup("imports", 1280, "Imported libraries and functions (hashed)"),
    FeatureGroup("exports", 128, "Exported functions (hashed)"),
    FeatureGroup("datadirectories", 30, "First 15 data directories (size + RVA)"),
]

EMBER_V2_TOTAL_DIM = sum(fg.dim for fg in EMBER_V2_FEATURE_GROUPS)  # 2381
EMBER_V2_FEATURE_VERSION = 2
EMBER_V2_LIEF_VERSION = "0.9.0"  # Reference version


class EMBERFeatureExtractor:
    """
    EMBER v2 Feature Extractor.
    
    Produces a 2,381-dimensional float32 feature vector compatible with
    the official EMBER v2 reference implementation.
    """
    
    # Feature group order must match reference implementation exactly
    FEATURE_GROUP_NAMES = [
        "histogram", "byteentropy", "strings", "general",
        "header", "section", "imports", "exports", "datadirectories"
    ]
    
    # Feature group dimensions (must match reference exactly)
    FEATURE_GROUP_DIMS = {
        "histogram": 256,
        "byteentropy": 256,
        "strings": 104,
        "general": 10,
        "header": 62,
        "section": 255,
        "imports": 1280,
        "exports": 128,
        "datadirectories": 30,
    }
    
    TOTAL_DIM = 2381
    FEATURE_VERSION = 2
    
    def __init__(self, feature_version: int = 2, print_warning: bool = True):
        """
        Initialize EMBER v2 feature extractor.
        
        Args:
            feature_version: Must be 2 (EMBER v2)
            print_warning: Print LIEF version compatibility warnings
        """
        if feature_version != 2:
            raise ValueError("Only EMBER feature version 2 is supported")
        
        self._feature_version = feature_version
        self.print_warning = print_warning
        
        if lief is not None and print_warning:
            if not LIEF_HAS_DATA_DIRECTORIES:
                print(f"WARNING: EMBER feature version 2 requires LIEF 0.9.0+ for DataDirectories")
                print(f"WARNING:   LIEF version {lief.__version__} found instead")
        
        # LIEF version compatibility check
        if lief is not None and print_warning:
            if not LIEF_HAS_DATA_DIRECTORIES:
                print(f"WARNING: EMBER feature version 2 requires LIEF 0.9.0+ for DataDirectories")
                print(f"WARNING:   LIEF version {lief.__version__} found instead")
        
        # Initialize feature hashers with exact reference parameters
        # Using alternate_sign=True to match the official elastic/ember reference
        # implementation, which does not override the parameter and uses sklearn's
        # default of alternate_sign=True.
        self._hashers = {
            "libraries": FeatureHasher(256, input_type="string", alternate_sign=True),
            "imports": FeatureHasher(1024, input_type="string", alternate_sign=True),
            "exports": FeatureHasher(128, input_type="string", alternate_sign=True),
            "section_sizes": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "section_entropy": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "section_vsize": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "entry_name": FeatureHasher(50, input_type="string", alternate_sign=True),
            "characteristics": FeatureHasher(50, input_type="string", alternate_sign=True),
            "coff_machine": FeatureHasher(10, input_type="string", alternate_sign=True),
            "coff_characteristics": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_subsystem": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_dll_characteristics": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_magic": FeatureHasher(10, input_type="string", alternate_sign=True),
        }
        
        # Regex patterns (matching reference exactly)
        self._allstrings = re.compile(rb'[\x20-\x7f]{5,}')
        self._paths = re.compile(b'c:\\\\', re.IGNORECASE)
        self._urls = re.compile(b'https?://', re.IGNORECASE)
        self._registry = re.compile(b'HKEY_')
        self._mz = re.compile(b'MZ')
        
        # Data directory name order (must match reference exactly)
        self._data_dir_names = [
            "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
            "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
            "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
            "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"
        ]
    
    @property
    def total_dim(self) -> int:
        return self.TOTAL_DIM
    
    @property
    def feature_version(self) -> int:
        return self._feature_version
    
    def _get_lief_binary(self, bytez: bytes):
        """Parse PE bytes with LIEF, return None on failure."""
        if lief is None:
            return None
        lief_errors = (
            lief.lief_errors.file_format_error, lief.lief_errors.file_error,
            lief.lief_errors.runtime_error, lief.lief_errors.parsing_error,
            lief.lief_errors.read_out_of_bound, RuntimeError
        )
        try:
            return lief.PE.parse(list(bytez))
        except lief_errors:
            return None
        except Exception:
            raise
    
    # ==================== Feature Group Implementations ====================
    
    def _extract_histogram(self, bytez: bytes) -> np.ndarray:
        """Byte histogram (256 dims) - normalized."""
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        counts = counts.astype(np.float32)
        total = counts.sum()
        if total > 0:
            counts = counts / total
        return counts.astype(np.float32)
    
    def _extract_byte_entropy(self, bytez: bytes) -> np.ndarray:
        """Byte-entropy histogram (16x16 = 256 dims) - normalized."""
        window = 2048
        step = 1024
        
        output = np.zeros((16, 16), dtype=np.int32)
        arr = np.frombuffer(bytez, dtype=np.uint8)
        
        if arr.shape[0] < window:
            hbin, counts = self._entropy_bin_counts(arr, window)
            output[hbin, :] += counts
        else:
            # Strided rolling windows
            shape = arr.shape[:-1] + (arr.shape[-1] - window + 1, window)
            strides = arr.strides + (arr.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(arr, shape=shape, strides=strides)[::step, :]
            
            for block in blocks:
                hbin, counts = self._entropy_bin_counts(block, window)
                output[hbin, :] += counts
        
        flat = output.flatten().astype(np.float32)
        total = flat.sum()
        if total > 0:
            flat = flat / total
        return flat
    
    def _entropy_bin_counts(self, block: np.ndarray, window: int) -> tuple:
        """Compute entropy bin and byte histogram for a block."""
        # Coarse histogram: 16 bins (byte >> 4)
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        h = np.sum(-p[wh] * np.log2(p[wh])) * 2  # *2 because 256->16 bins (8 bits -> 4 bits)
        
        hbin = int(h * 2)  # 16 bins for entropy 0-8 bits
        if hbin == 16:
            hbin = 15
        return hbin, c
    
    def _extract_strings(self, bytez: bytes) -> np.ndarray:
        """Extract string features (104 dims)."""
        allstrings = self._allstrings.findall(bytez)
        
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            
            # Printable character distribution (0x20-0x7F = 96 chars)
            as_shifted = [b - 0x20 for s in allstrings for b in s]
            c = np.bincount(as_shifted, minlength=96).astype(np.float32)
            csum = c.sum()
            if csum > 0:
                p = c / csum
                wh = np.where(c)[0]
                H = float(np.sum(-p[wh] * np.log2(p[wh])))
            else:
                H = 0.0
            csum = float(csum)
        else:
            avlength = 0.0
            c = np.zeros(96, dtype=np.float32)
            H = 0.0
            csum = 0.0
        
        # String-based indicators
        paths = len(self._paths.findall(bytez))
        urls = len(self._urls.findall(bytez))
        registry = len(self._registry.findall(bytez))
        mz_count = len(self._mz.findall(bytez))
        
        # Normalize printable distribution
        if csum > 0:
            printable_dist = (c / csum).astype(np.float32)
        else:
            printable_dist = np.zeros(96, dtype=np.float32)
        
        return np.hstack([
            np.float32(len(allstrings)),
            np.float32(avlength),
            np.float32(csum),
            printable_dist,
            np.float32(H),
            np.float32(paths),
            np.float32(urls),
            np.float32(registry),
            np.float32(mz_count),
        ]).astype(np.float32)
    
    def _extract_general(self, bytez: bytes, lief_binary) -> np.ndarray:
        """General file info (10 dims)."""
        if lief_binary is None:
            return np.array([
                len(bytez), 0, 0, 0, 0, 0, 0, 0, 0, 0
            ], dtype=np.float32)
        
        # Handle exports count (LIEF version differences)
        if LIEF_HAS_EXPORT_OBJECT:
            exports_count = len(lief_binary.exported_functions)
        else:
            exports_count = len(lief_binary.exported_functions)
        
        return np.array([
            len(bytez),
            lief_binary.virtual_size,
            int(lief_binary.has_debug),
            exports_count,
            len(lief_binary.imported_functions),
            int(lief_binary.has_relocations),
            int(lief_binary.has_resources),
            int(lief_binary.has_signatures) if LIEF_HAS_SIGNATURE else int(lief_binary.has_signature),
            int(lief_binary.has_tls),
            len(lief_binary.symbols),
        ], dtype=np.float32)
    
    def _extract_header(self, bytez: bytes, lief_binary) -> np.ndarray:
        """Header info (62 dims)."""
        if lief_binary is None:
            return np.zeros(62, dtype=np.float32)
        
        # COFF header
        coff_timestamp = float(lief_binary.header.time_date_stamps)
        coff_machine = str(lief_binary.header.machine).split('.')[-1]
        coff_chars = [str(c).split('.')[-1] for c in lief_binary.header.characteristics_list]
        
        # Optional header
        opt = lief_binary.optional_header
        opt_subsystem = str(opt.subsystem).split('.')[-1]
        opt_dll_chars = [str(c).split('.')[-1] for c in opt.dll_characteristics_lists]
        opt_magic = str(opt.magic).split('.')[-1]
        
        # Feature hashing for categorical fields (matching reference exactly)
        machine_hashed = self._hashers["coff_machine"].transform([[coff_machine]]).toarray()[0]
        chars_hashed = self._hashers["coff_characteristics"].transform([coff_chars]).toarray()[0]
        subsystem_hashed = self._hashers["optional_subsystem"].transform([[opt_subsystem]]).toarray()[0]
        dll_chars_hashed = self._hashers["optional_dll_characteristics"].transform([opt_dll_chars]).toarray()[0]
        magic_hashed = self._hashers["optional_magic"].transform([[opt_magic]]).toarray()[0]
        
        return np.hstack([
            coff_timestamp,
            machine_hashed,                    # 10
            chars_hashed,                      # 10
            subsystem_hashed,                  # 10
            dll_chars_hashed,                  # 10
            magic_hashed,                      # 10
            float(opt.major_image_version),
            float(opt.minor_image_version),
            float(opt.major_linker_version),
            float(opt.minor_linker_version),
            float(opt.major_operating_system_version),
            float(opt.minor_operating_system_version),
            float(opt.major_subsystem_version),
            float(opt.minor_subsystem_version),
            float(opt.sizeof_code),
            float(opt.sizeof_headers),
            float(opt.sizeof_heap_commit),
        ]).astype(np.float32)
    
    def _extract_section(self, bytez: bytes, lief_binary) -> np.ndarray:
        """Section info (255 dims)."""
        if lief_binary is None:
            return np.zeros(255, dtype=np.float32)
        
        # Entry section name
        try:
            if LIEF_HAS_SECTION_FROM_RVA:
                section = lief_binary.section_from_rva(lief_binary.entrypoint - lief_binary.imagebase)
                entry_name = section.name if section else ""
            else:
                entry_name = lief_binary.section_from_offset(lief_binary.entrypoint).name
        except (AttributeError, lief.not_found):
            entry_name = ""
            for s in lief_binary.sections:
                if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                    entry_name = s.name
                    break
        
        # Section attributes
        sections = []
        for s in lief_binary.sections:
            props = [str(c).split('.')[-1] for c in s.characteristics_lists]
            sections.append({
                'name': s.name,
                'size': s.size,
                'entropy': s.entropy,
                'vsize': s.virtual_size,
                'props': props
            })
        
        # General section stats (5)
        general = np.array([
            len(sections),
            sum(1 for s in sections if s['size'] == 0),
            sum(1 for s in sections if s['name'] == ""),
            sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),
            sum(1 for s in sections if 'MEM_WRITE' in s['props']),
        ], dtype=np.float32)
        
        # Hashed section attributes (50 each = 200)
        section_sizes = [(s['name'], s['size']) for s in sections]
        section_entropy = [(s['name'], s['entropy']) for s in sections]
        section_vsize = [(s['name'], s['vsize']) for s in sections]
        
        sizes_hashed = self._hashers["section_sizes"].transform([section_sizes]).toarray()[0]
        entropy_hashed = self._hashers["section_entropy"].transform([section_entropy]).toarray()[0]
        vsize_hashed = self._hashers["section_vsize"].transform([section_vsize]).toarray()[0]
        entry_hashed = self._hashers["entry_name"].transform([[entry_name]]).toarray()[0]
        
        # Entry section characteristics (50)
        entry_props = []
        for s in sections:
            if s['name'] == entry_name:
                entry_props = s['props']
                break
        chars_hashed = self._hashers["characteristics"].transform([entry_props]).toarray()[0]
        
        return np.hstack([
            general, sizes_hashed, entropy_hashed, vsize_hashed, entry_hashed, chars_hashed
        ]).astype(np.float32)
    
    def _extract_imports(self, bytez: bytes, lief_binary) -> np.ndarray:
        """Imports info (1280 dims)."""
        if lief_binary is None:
            return np.zeros(1280, dtype=np.float32)
        
        imports = {}
        for lib in lief_binary.imports:
            lib_name = lib.name.lower()
            if lib_name not in imports:
                imports[lib_name] = []
            for entry in lib.entries:
                if entry.is_ordinal:
                    imports[lib_name].append(f"ordinal{entry.ordinal}")
                else:
                    imports[lib_name].append(entry.name[:10000])
        
        # Libraries (256)
        libraries = list(set(imports.keys()))
        lib_hashed = self._hashers["libraries"].transform([libraries]).toarray()[0]
        
        # Imported functions (1024) - "library:function" pairs
        import_pairs = [lib + ':' + e for lib, elist in imports.items() for e in elist]
        imports_hashed = self._hashers["imports"].transform([import_pairs]).toarray()[0]
        
        return np.hstack([lib_hashed, imports_hashed]).astype(np.float32)
    
    def _extract_exports(self, bytez: bytes, lief_binary) -> np.ndarray:
        """Exports info (128 dims)."""
        if lief_binary is None:
            return np.zeros(128, dtype=np.float32)
        
        if LIEF_HAS_EXPORT_OBJECT:
            exports = [exp.name[:10000] for exp in lief_binary.exported_functions]
        else:
            exports = [exp[:10000] for exp in lief_binary.exported_functions]
        
        exports_hashed = self._hashers["exports"].transform([exports]).toarray()[0]
        return exports_hashed.astype(np.float32)
    
    def _extract_data_directories(self, bytez: bytes, lief_binary) -> np.ndarray:
        """Data directories (30 dims) - Feature Version 2 only."""
        features = np.zeros(30, dtype=np.float32)
        
        if lief_binary is None:
            return features
        
        for i, dir_name in enumerate(self._data_dir_names):
            if i < len(lief_binary.data_directories):
                dd = lief_binary.data_directories[i]
                features[2*i] = float(dd.size)
                features[2*i + 1] = float(dd.rva)
        
        return features
    
    # ==================== Public API ====================
    
    def raw_features(self, bytez: bytes) -> Dict[str, Any]:
        """Extract raw features from PE bytes."""
        lief_binary = self._get_lief_binary(bytez)
        
        features = {
            "sha256": hashlib.sha256(bytez).hexdigest(),
            "histogram": self._extract_histogram(bytez).tolist(),
            "byteentropy": self._extract_byte_entropy(bytez).tolist(),
            "strings": self._extract_strings(bytez).tolist(),
            "general": self._extract_general(bytez, lief_binary).tolist(),
            "header": self._extract_header(bytez, lief_binary).tolist(),
            "section": self._extract_section(bytez, lief_binary).tolist(),
            "imports": self._extract_imports(bytez, lief_binary).tolist(),
            "exports": self._extract_exports(bytez, lief_binary).tolist(),
        }
        
        if LIEF_HAS_DATA_DIRECTORIES:
            features["datadirectories"] = self._extract_data_directories(bytez, lief_binary).tolist()
        else:
            features["datadirectories"] = []
        
        return features
    
    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """Extract 2,381-dimensional feature vector from PE bytes.
        
        Returns:
            float32 array of shape (2381,) for valid PE files,
            zeros array for invalid/unsupported files.
        """
        raw = self.raw_features(bytez)
        return self.process_raw_features(raw)
    
    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        """Convert raw features to final feature vector."""
        vec_parts = [
            np.array(raw_obj["histogram"], dtype=np.float32),
            np.array(raw_obj["byteentropy"], dtype=np.float32),
            np.array(raw_obj["strings"], dtype=np.float32),
            np.array(raw_obj["general"], dtype=np.float32),
            np.array(raw_obj["header"], dtype=np.float32),
            np.array(raw_obj["section"], dtype=np.float32),
            np.array(raw_obj["imports"], dtype=np.float32),
            np.array(raw_obj["exports"], dtype=np.float32),
        ]
        
        if "datadirectories" in raw_obj and raw_obj["datadirectories"]:
            vec_parts.append(np.array(raw_obj["datadirectories"], dtype=np.float32))
        else:
            vec_parts.append(np.zeros(30, dtype=np.float32))
        
        result = np.hstack(vec_parts).astype(np.float32)
        
        # Validate dimension
        if result.shape[0] != self.TOTAL_DIM:
            raise ValueError(f"Feature vector dimension mismatch: expected {self.TOTAL_DIM}, got {result.shape[0]}")
        
        return result
    
    def get_feature_metadata(self) -> Dict[str, Any]:
        """Return feature extraction metadata."""
        return {
            "feature_version": self.FEATURE_VERSION,
            "total_dim": self.TOTAL_DIM,
            "dtype": "float32",
            "feature_groups": [
                {"name": fg.name, "dim": fg.dim, "description": fg.description}
                for fg in EMBER_V2_FEATURE_GROUPS
            ],
            "lief_version": LIEF_VERSION,
            "sklearn_version": __import__('sklearn').__version__,
            "numpy_version": np.__version__,
        }


# Convenience function
def extract_ember_v2_features(bytez: bytes, feature_version: int = 2) -> np.ndarray:
    """Convenience function to extract EMBER v2 features."""
    extractor = EMBERFeatureExtractor(feature_version=feature_version)
    return extractor.feature_vector(bytez)