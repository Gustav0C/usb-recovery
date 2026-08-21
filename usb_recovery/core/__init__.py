"""
Core module - Motor de carving y funciones principales
"""

from .carver import FileCarver
from .signatures import FILE_SIGNATURES
from .validator import FileValidator
from .deduplicator import FileDeduplicator, fast_hash
from .forensic import ForensicEngine, ForensicScanCoordinator, FileCandidate
from .performance import (
    MultiPatternSearcher, NativeDeviceReader, StandardDeviceReader,
    create_reader, ParallelScanner, OffsetCache,
)
