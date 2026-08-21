"""
USB Recovery Tool - Herramienta de recuperación de archivos eliminados de USB
"""

__version__ = '2.0.0'
__author__ = 'USB Recovery Team'

# Re-exports for backward compatibility
from .core.signatures import FILE_SIGNATURES
from .core.carver import FileCarver
from .core.validator import FileValidator
from .core.deduplicator import FileDeduplicator, fast_hash
from .platform.detector import get_detector, DeviceDetector, DeviceInfo
from .utils.logging import ScanLogger
from .utils.config import ScanConfig
