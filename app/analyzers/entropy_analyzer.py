"""
Module 05: Entropy Analyzer

Responsibility:
Calculates Shannon entropy for the entire binary and individual PE sections.

Formula:
H(X) = -Σ p(x) * log2(p(x))

Entropy Value Range:
0.0 (minimum randomness / single repeated byte) to 8.0 (maximum randomness / uniform distribution).

Configurable Classifications:
- LOW       : [0.0, 4.0)   (repetitive patterns, zero-padding, sparse tables)
- NORMAL    : [4.0, 6.8)   (standard compiled code, standard text, PE headers)
- HIGH      : [6.8, 7.5)   (dense compiled code, compressed media, light packing)
- VERY_HIGH : [7.5, 8.0]   (heavily packed, encrypted, or compressed data)

Defensive & Educational Principles:
- Strictly static in-memory calculation; NEVER executes the file.
- High entropy does NOT automatically equal malware.
- High entropy indicates compression, encryption, packing, or obfuscation, which can be legitimate or suspicious depending on context.
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import pefile

from app.core.logger import logger

# Configurable Entropy Classification Thresholds
ENTROPY_THRESHOLDS = {
    "LOW_MAX": 4.0,
    "NORMAL_MAX": 6.8,
    "HIGH_MAX": 7.5,
    "VERY_HIGH_MAX": 8.0,
}


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes mathematical Shannon Entropy for an arbitrary byte sequence.

    Args:
        data: Raw byte sequence.

    Returns:
        Entropy float value bounded between 0.0 and 8.0.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    # Clamp to [0.0, 8.0] to guard against floating-point inaccuracies
    return max(0.0, min(8.0, entropy))


def classify_entropy_score(entropy: float) -> str:
    """
    Classifies a Shannon entropy score into configurable qualitative tiers.

    Args:
        entropy: Calculated entropy value [0.0, 8.0].

    Returns:
        One of 'LOW', 'NORMAL', 'HIGH', 'VERY_HIGH'.
    """
    if entropy < ENTROPY_THRESHOLDS["LOW_MAX"]:
        return "LOW"
    elif entropy < ENTROPY_THRESHOLDS["NORMAL_MAX"]:
        return "NORMAL"
    elif entropy < ENTROPY_THRESHOLDS["HIGH_MAX"]:
        return "HIGH"
    else:
        return "VERY_HIGH"


@dataclass
class SectionEntropyResult:
    """
    Entropy measurement for an individual PE section.
    """
    name: str
    entropy: float
    classification: str
    raw_size: int = 0
    virtual_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 05 section schema."""
        return {
            "name": self.name,
            "entropy": round(self.entropy, 2),
            "classification": self.classification,
        }


@dataclass
class EntropyAnalysisResult:
    """
    Complete outcome of the Entropy Analysis.
    """
    file_entropy: float = 0.0
    file_classification: str = "LOW"
    sections: List[SectionEntropyResult] = field(default_factory=list)
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 05 output contract dictionary."""
        return {
            "file_entropy": round(self.file_entropy, 2),
            "sections": [sec.to_dict() for sec in self.sections],
        }


class EntropyAnalyzer:
    """
    Shannon Entropy Analyzer Engine for Files and PE Sections.
    """

    def compute_entropy(self, data: bytes) -> float:
        """Helper to calculate raw entropy on byte data."""
        return calculate_shannon_entropy(data)

    def classify(self, entropy: float) -> str:
        """Helper to classify an entropy score."""
        return classify_entropy_score(entropy)

    @staticmethod
    def _sanitize_name(name_bytes: bytes) -> str:
        """Cleans null-padded section names."""
        try:
            return name_bytes.decode("latin-1", errors="replace").split("\x00")[0].strip()
        except Exception:
            return "unknown"

    def analyze_bytes(self, data: bytes) -> EntropyAnalysisResult:
        """
        Calculates whole-file entropy and individual PE section entropies.

        Args:
            data: Raw binary byte stream.

        Returns:
            EntropyAnalysisResult object.
        """
        if not data:
            return EntropyAnalysisResult(
                file_entropy=0.0,
                file_classification="LOW",
                sections=[],
                is_valid=True,
                error_message=None
            )

        # 1. Whole-file entropy calculation
        overall_entropy = calculate_shannon_entropy(data)
        overall_class = classify_entropy_score(overall_entropy)

        # 2. Check if data is a PE binary for per-section analysis
        section_results: List[SectionEntropyResult] = []

        if len(data) >= 64 and data[:2] == b"MZ":
            try:
                pe = pefile.PE(data=data, fast_load=False)
                for sec in getattr(pe, "sections", []):
                    raw_name = getattr(sec, "Name", b"")
                    sec_name = self._sanitize_name(raw_name)
                    r_size = getattr(sec, "SizeOfRawData", 0)
                    v_size = getattr(sec, "Misc_VirtualSize", 0)

                    # Extract raw section bytes safely
                    sec_data = sec.get_data()
                    sec_entropy = calculate_shannon_entropy(sec_data) if sec_data else 0.0
                    sec_class = classify_entropy_score(sec_entropy)

                    section_results.append(SectionEntropyResult(
                        name=sec_name,
                        entropy=sec_entropy,
                        classification=sec_class,
                        raw_size=r_size,
                        virtual_size=v_size,
                    ))

                pe.close()
            except pefile.PEFormatError:
                # File has MZ header but is not a full PE; file_entropy is still valid
                logger.info("Binary has MZ header but is non-standard PE; skipping section breakdown.")
            except Exception as err:
                logger.warning(f"Error extracting section entropy: {err}")

        return EntropyAnalysisResult(
            file_entropy=overall_entropy,
            file_classification=overall_class,
            sections=section_results,
            is_valid=True,
            error_message=None
        )

    def analyze_file(self, file_path: Union[str, Path]) -> EntropyAnalysisResult:
        """
        Loads a file from disk and calculates its entropy safely without execution.

        Args:
            file_path: Path to target file.

        Returns:
            EntropyAnalysisResult object.
        """
        target = Path(file_path)
        if not target.exists() or not target.is_file():
            return EntropyAnalysisResult(
                file_entropy=0.0,
                file_classification="LOW",
                sections=[],
                is_valid=False,
                error_message=f"Target file not found at path: {file_path}"
            )

        try:
            with open(target, "rb") as f:
                content = f.read()
            return self.analyze_bytes(content)
        except PermissionError as pe:
            return EntropyAnalysisResult(
                file_entropy=0.0,
                file_classification="LOW",
                sections=[],
                is_valid=False,
                error_message=f"Permission denied reading file '{file_path}': {pe}"
            )
        except Exception as e:
            return EntropyAnalysisResult(
                file_entropy=0.0,
                file_classification="LOW",
                sections=[],
                is_valid=False,
                error_message=f"Failed to read file '{file_path}': {str(e)}"
            )


# Global singleton instance
entropy_analyzer_service = EntropyAnalyzer()


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 05: Entropy Analyzer Demo")
    print("=" * 68)

    analyzer = EntropyAnalyzer()

    # Mathematical Verification Vectors
    all_zeros = b"\x00" * 1024
    uniform_256 = bytes(range(256)) * 4
    two_state = b"AB" * 512
    four_state = b"ABCD" * 256

    print(f"All Zeros Entropy (Expected 0.0) : {analyzer.compute_entropy(all_zeros):.4f} [{analyzer.classify(analyzer.compute_entropy(all_zeros))}]")
    print(f"Two-State Entropy (Expected 1.0) : {analyzer.compute_entropy(two_state):.4f} [{analyzer.classify(analyzer.compute_entropy(two_state))}]")
    print(f"Four-State Entropy (Expected 2.0): {analyzer.compute_entropy(four_state):.4f} [{analyzer.classify(analyzer.compute_entropy(four_state))}]")
    print(f"Uniform 256 Entropy (Expected 8.0): {analyzer.compute_entropy(uniform_256):.4f} [{analyzer.classify(analyzer.compute_entropy(uniform_256))}]")

    print("=" * 68)
