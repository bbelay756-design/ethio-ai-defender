"""
Reference EMBER v2 Feature Extractor for ETHIO-AI Defender.

Transcribes the exact reference implementation from elastic/ember/ember/features.py
(Feature Version 2) to serve as an in-process, dependency-clean reference standard
for empirical feature parity validation without requiring unapproved package installations.

Reference Source:
https://github.com/elastic/ember/blob/master/ember/features.py
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.feature_extraction import FeatureHasher

try:
    import lief
except ImportError:
    lief = None


class ReferenceByteHistogram:
    """Byte histogram over the entire binary file."""
    dim = 256

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[int]:
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        if total > 0:
            return (counts / total).astype(np.float32)
        return np.zeros(256, dtype=np.float32)


class ReferenceByteEntropyHistogram:
    """2D byte/entropy joint histogram (16x16) over binary windows."""
    dim = 256

    def __init__(self, step: int = 1024, window: int = 2048):
        self.step = step
        self.window = window

    def _entropy_bin_counts(self, block: np.ndarray) -> Tuple[int, np.ndarray]:
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        h = np.sum(-p[wh] * np.log2(p[wh])) * 2
        hbin = int(h * 2)
        if hbin == 16:
            hbin = 15
        return hbin, c

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[int]:
        output = np.zeros((16, 16), dtype=np.int32)
        arr = np.frombuffer(bytez, dtype=np.uint8)
        if arr.shape[0] < self.window:
            hbin, counts = self._entropy_bin_counts(arr)
            output[hbin, :] += counts
        else:
            shape = arr.shape[:-1] + (arr.shape[-1] - self.window + 1, self.window)
            strides = arr.strides + (arr.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(arr, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                hbin, counts = self._entropy_bin_counts(block)
                output[hbin, :] += counts
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        if total > 0:
            return (counts / total).astype(np.float32)
        return np.zeros(256, dtype=np.float32)


class ReferenceStringExtractor:
    """Extract string statistics and printable character distribution."""
    dim = 104

    def __init__(self):
        self._allstrings = re.compile(rb'[\x20-\x7f]{5,}')
        self._paths = re.compile(b'c:\\\\', re.IGNORECASE)
        self._urls = re.compile(b'https?://', re.IGNORECASE)
        self._registry = re.compile(b'HKEY_')
        self._mz = re.compile(b'MZ')

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Any]:
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            as_shifted = [b - 0x20 for s in allstrings for b in s]
            c = np.bincount(as_shifted, minlength=96)
            csum = float(c.sum())
            if csum > 0:
                p = c.astype(np.float32) / csum
                wh = np.where(c)[0]
                H = float(np.sum(-p[wh] * np.log2(p[wh])))
                pdist = (c / csum).tolist()
            else:
                H = 0.0
                pdist = [0.0] * 96
        else:
            avlength = 0.0
            csum = 0.0
            pdist = [0.0] * 96
            H = 0.0

        return {
            "numstrings": len(allstrings),
            "avlength": float(avlength),
            "printables": float(csum),
            "printabledist": pdist,
            "entropy": float(H),
            "paths": len(self._paths.findall(bytez)),
            "urls": len(self._urls.findall(bytez)),
            "registry": len(self._registry.findall(bytez)),
            "MZ": len(self._mz.findall(bytez)),
        }

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        pdist = np.array(raw_obj.get("printabledist", [0.0] * 96), dtype=np.float32)
        if pdist.shape != (96,):
            pdist = np.zeros(96, dtype=np.float32)
        scalars = [
            float(raw_obj.get("numstrings", 0)),
            float(raw_obj.get("avlength", 0.0)),
            float(raw_obj.get("printables", 0.0)),
            float(raw_obj.get("entropy", 0.0)),
            float(raw_obj.get("paths", 0)),
            float(raw_obj.get("urls", 0)),
            float(raw_obj.get("registry", 0)),
            float(raw_obj.get("MZ", 0)),
        ]
        return np.hstack([
            np.float32(scalars[0]),
            np.float32(scalars[1]),
            np.float32(scalars[2]),
            pdist,
            np.float32(scalars[3]),
            np.float32(scalars[4]),
            np.float32(scalars[5]),
            np.float32(scalars[6]),
            np.float32(scalars[7]),
        ]).astype(np.float32)


class ReferenceGeneralFileInfo:
    """General file information."""
    dim = 10

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Any]:
        if lief_binary is None:
            return {
                "size": len(bytez), "vsize": 0, "has_debug": 0, "exports": 0,
                "imports": 0, "has_relocations": 0, "has_resources": 0,
                "has_signature": 0, "has_tls": 0, "symbols": 0
            }
        has_sig = int(lief_binary.has_signatures) if hasattr(lief_binary, "has_signatures") else int(lief_binary.has_signature)
        return {
            "size": len(bytez),
            "vsize": lief_binary.virtual_size,
            "has_debug": int(lief_binary.has_debug),
            "exports": len(lief_binary.exported_functions),
            "imports": len(lief_binary.imported_functions),
            "has_relocations": int(lief_binary.has_relocations),
            "has_resources": int(lief_binary.has_resources),
            "has_signature": has_sig,
            "has_tls": int(lief_binary.has_tls),
            "symbols": len(lief_binary.symbols),
        }

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        return np.array([
            float(raw_obj.get("size", 0)),
            float(raw_obj.get("vsize", 0)),
            float(raw_obj.get("has_debug", 0)),
            float(raw_obj.get("exports", 0)),
            float(raw_obj.get("imports", 0)),
            float(raw_obj.get("has_relocations", 0)),
            float(raw_obj.get("has_resources", 0)),
            float(raw_obj.get("has_signature", 0)),
            float(raw_obj.get("has_tls", 0)),
            float(raw_obj.get("symbols", 0)),
        ], dtype=np.float32)


class ReferenceHeaderFileInfo:
    """Header information from COFF and Optional headers."""
    dim = 62

    def __init__(self):
        self._hashers = {
            "coff_machine": FeatureHasher(10, input_type="string", alternate_sign=True),
            "coff_characteristics": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_subsystem": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_dll_characteristics": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_magic": FeatureHasher(10, input_type="string", alternate_sign=True),
        }

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Any]:
        if lief_binary is None:
            return {
                "coff": {"timestamp": 0, "machine": "", "characteristics": []},
                "optional": {
                    "subsystem": "", "dll_characteristics": [], "magic": "",
                    "major_image_version": 0, "minor_image_version": 0,
                    "major_linker_version": 0, "minor_linker_version": 0,
                    "major_operating_system_version": 0, "minor_operating_system_version": 0,
                    "major_subsystem_version": 0, "minor_subsystem_version": 0,
                    "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0
                }
            }
        opt = lief_binary.optional_header
        return {
            "coff": {
                "timestamp": float(lief_binary.header.time_date_stamps),
                "machine": str(lief_binary.header.machine).split('.')[-1],
                "characteristics": [str(c).split('.')[-1] for c in lief_binary.header.characteristics_list],
            },
            "optional": {
                "subsystem": str(opt.subsystem).split('.')[-1],
                "dll_characteristics": [str(c).split('.')[-1] for c in opt.dll_characteristics_lists],
                "magic": str(opt.magic).split('.')[-1],
                "major_image_version": float(opt.major_image_version),
                "minor_image_version": float(opt.minor_image_version),
                "major_linker_version": float(opt.major_linker_version),
                "minor_linker_version": float(opt.minor_linker_version),
                "major_operating_system_version": float(opt.major_operating_system_version),
                "minor_operating_system_version": float(opt.minor_operating_system_version),
                "major_subsystem_version": float(opt.major_subsystem_version),
                "minor_subsystem_version": float(opt.minor_subsystem_version),
                "sizeof_code": float(opt.sizeof_code),
                "sizeof_headers": float(opt.sizeof_headers),
                "sizeof_heap_commit": float(opt.sizeof_heap_commit),
            }
        }

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        coff = raw_obj.get("coff", {})
        opt = raw_obj.get("optional", {})
        coff_ts = float(coff.get("timestamp", 0))
        machine = str(coff.get("machine", "")).split('.')[-1]
        chars = [str(c).split('.')[-1] for c in coff.get("characteristics", [])]
        subsystem = str(opt.get("subsystem", "")).split('.')[-1]
        dll_chars = [str(c).split('.')[-1] for c in opt.get("dll_characteristics", [])]
        magic = str(opt.get("magic", "")).split('.')[-1]

        h_mach = self._hashers["coff_machine"].transform([[machine]]).toarray()[0]
        h_chars = self._hashers["coff_characteristics"].transform([chars]).toarray()[0]
        h_sub = self._hashers["optional_subsystem"].transform([[subsystem]]).toarray()[0]
        h_dll = self._hashers["optional_dll_characteristics"].transform([dll_chars]).toarray()[0]
        h_mag = self._hashers["optional_magic"].transform([[magic]]).toarray()[0]

        numerics = [
            float(opt.get("major_image_version", 0)),
            float(opt.get("minor_image_version", 0)),
            float(opt.get("major_linker_version", 0)),
            float(opt.get("minor_linker_version", 0)),
            float(opt.get("major_operating_system_version", 0)),
            float(opt.get("minor_operating_system_version", 0)),
            float(opt.get("major_subsystem_version", 0)),
            float(opt.get("minor_subsystem_version", 0)),
            float(opt.get("sizeof_code", 0)),
            float(opt.get("sizeof_headers", 0)),
            float(opt.get("sizeof_heap_commit", 0)),
        ]
        return np.hstack([coff_ts, h_mach, h_chars, h_sub, h_dll, h_mag, numerics]).astype(np.float32)


class ReferenceSectionInfo:
    """Section statistics and hashed attributes."""
    dim = 255

    def __init__(self):
        self._hashers = {
            "section_sizes": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "section_entropy": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "section_vsize": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "entry_name": FeatureHasher(50, input_type="string", alternate_sign=True),
            "characteristics": FeatureHasher(50, input_type="string", alternate_sign=True),
        }

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Any]:
        if lief_binary is None:
            return {"entry": "", "sections": []}
        try:
            if hasattr(lief_binary, "section_from_rva"):
                sec = lief_binary.section_from_rva(lief_binary.entrypoint - lief_binary.imagebase)
                entry_name = sec.name if sec else ""
            else:
                entry_name = lief_binary.section_from_offset(lief_binary.entrypoint).name
        except Exception:
            entry_name = ""

        sections = []
        for s in lief_binary.sections:
            props = [str(c).split('.')[-1] for c in s.characteristics_lists]
            sections.append({
                "name": s.name,
                "size": s.size,
                "entropy": s.entropy,
                "vsize": s.virtual_size,
                "props": props,
            })
        return {"entry": entry_name, "sections": sections}

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        entry = str(raw_obj.get("entry", ""))
        sections = raw_obj.get("sections", [])
        general = np.array([
            len(sections),
            sum(1 for s in sections if s.get('size', 0) == 0),
            sum(1 for s in sections if s.get('name', '') == ""),
            sum(1 for s in sections if 'MEM_READ' in s.get('props', []) and 'MEM_EXECUTE' in s.get('props', [])),
            sum(1 for s in sections if 'MEM_WRITE' in s.get('props', [])),
        ], dtype=np.float32)

        s_sizes = [(str(s.get('name', '')), float(s.get('size', 0))) for s in sections]
        s_ent = [(str(s.get('name', '')), float(s.get('entropy', 0.0))) for s in sections]
        s_vsz = [(str(s.get('name', '')), float(s.get('vsize', 0))) for s in sections]

        h_sizes = self._hashers["section_sizes"].transform([s_sizes]).toarray()[0]
        h_ent = self._hashers["section_entropy"].transform([s_ent]).toarray()[0]
        h_vsz = self._hashers["section_vsize"].transform([s_vsz]).toarray()[0]
        h_entry = self._hashers["entry_name"].transform([[entry]]).toarray()[0]

        entry_props = []
        for s in sections:
            if s.get('name') == entry:
                entry_props = [str(p).split('.')[-1] for p in s.get('props', [])]
                break
        h_chars = self._hashers["characteristics"].transform([entry_props]).toarray()[0]

        return np.hstack([general, h_sizes, h_ent, h_vsz, h_entry, h_chars]).astype(np.float32)


class ReferenceImportsInfo:
    """Imported libraries and functions."""
    dim = 1280

    def __init__(self):
        self._hashers = {
            "libraries": FeatureHasher(256, input_type="string", alternate_sign=True),
            "imports": FeatureHasher(1024, input_type="string", alternate_sign=True),
        }

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, List[str]]:
        imports: Dict[str, List[str]] = {}
        if lief_binary is None:
            return imports
        for lib in lief_binary.imports:
            lib_name = lib.name.lower()
            if lib_name not in imports:
                imports[lib_name] = []
            for entry in lib.entries:
                if entry.is_ordinal:
                    imports[lib_name].append(f"ordinal{entry.ordinal}")
                else:
                    imports[lib_name].append(entry.name[:10000])
        return imports

    def process_raw_features(self, raw_obj: Dict[str, List[str]]) -> np.ndarray:
        libraries = list(set([str(l).lower() for l in raw_obj.keys()]))
        import_pairs = [
            str(lib).lower() + ':' + str(e)[:10000]
            for lib, elist in raw_obj.items()
            for e in elist
        ]
        h_libs = self._hashers["libraries"].transform([libraries]).toarray()[0]
        h_imps = self._hashers["imports"].transform([import_pairs]).toarray()[0]
        return np.hstack([h_libs, h_imps]).astype(np.float32)


class ReferenceExportsInfo:
    """Exported function names."""
    dim = 128

    def __init__(self):
        self._hasher = FeatureHasher(128, input_type="string", alternate_sign=True)

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[str]:
        if lief_binary is None:
            return []
        return [exp.name[:10000] if hasattr(exp, "name") else str(exp)[:10000] for exp in lief_binary.exported_functions]

    def process_raw_features(self, raw_obj: List[str]) -> np.ndarray:
        exports = [str(exp)[:10000] for exp in raw_obj]
        return self._hasher.transform([exports]).toarray()[0].astype(np.float32)


class ReferenceDataDirectories:
    """Data directories (first 15 directories * [size, rva])."""
    dim = 30

    def __init__(self):
        self._data_dir_names = [
            "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
            "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
            "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
            "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"
        ]

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[Dict[str, float]]:
        res = []
        if lief_binary is None:
            return res
        for i, name in enumerate(self._data_dir_names):
            if i < len(lief_binary.data_directories):
                dd = lief_binary.data_directories[i]
                res.append({"name": name, "size": float(dd.size), "virtual_address": float(dd.rva)})
        return res

    def process_raw_features(self, raw_obj: List[Dict[str, float]]) -> np.ndarray:
        arr = np.zeros(30, dtype=np.float32)
        for i, d in enumerate(raw_obj[:15]):
            arr[2 * i] = float(d.get("size", 0.0))
            arr[2 * i + 1] = float(d.get("virtual_address", d.get("rva", 0.0)))
        return arr


class ReferencePEFeatureExtractor:
    """
    Exact reference implementation of EMBER Feature Version 2 orchestrator.
    Executes raw_features -> process_raw_features exactly as defined in elastic/ember.
    """
    TOTAL_DIM = 2381

    def __init__(self):
        self.extractors = [
            ReferenceByteHistogram(),
            ReferenceByteEntropyHistogram(),
            ReferenceStringExtractor(),
            ReferenceGeneralFileInfo(),
            ReferenceHeaderFileInfo(),
            ReferenceSectionInfo(),
            ReferenceImportsInfo(),
            ReferenceExportsInfo(),
            ReferenceDataDirectories(),
        ]

    def _get_lief_binary(self, bytez: bytes) -> Any:
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
            return None

    def raw_features(self, bytez: bytes) -> Dict[str, Any]:
        lief_binary = self._get_lief_binary(bytez)
        names = ["histogram", "byteentropy", "strings", "general", "header", "section", "imports", "exports", "datadirectories"]
        res = {"sha256": hashlib.sha256(bytez).hexdigest()}
        for name, ext in zip(names, self.extractors):
            res[name] = ext.raw_features(bytez, lief_binary)
        return res

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        raw = self.raw_features(bytez)
        names = ["histogram", "byteentropy", "strings", "general", "header", "section", "imports", "exports", "datadirectories"]
        vec_parts = [ext.process_raw_features(raw[name]) for name, ext in zip(names, self.extractors)]
        return np.hstack(vec_parts).astype(np.float32)
