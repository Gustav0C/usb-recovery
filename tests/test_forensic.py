"""
Tests unitarios para el motor forense.

Estos tests verifican:
- Validación de archivos
- Overlap dinámico
- Detección de firmas
- Reconstrucción de fragmentos
- Deduplicación
"""

import unittest
import struct
import sys
import os

# Agregar directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from usb_recovery.core.validator import FileValidator
from usb_recovery.core.forensic import (
    ForensicEngine, ForensicScanCoordinator, FileCandidate,
    DYNAMIC_OVERLAP, MIN_OVERLAP, get_dynamic_overlap,
)
from usb_recovery.core.signatures import FILE_SIGNATURES
from usb_recovery.core.deduplicator import FileDeduplicator, fast_hash


class TestFileValidator(unittest.TestCase):
    """Tests para la validación de archivos."""

    # ====================================================================
    # JPEG
    # ====================================================================

    def test_jpeg_valid(self):
        """JPEG con SOI y EOI válido."""
        data = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        is_valid, reason = FileValidator.validate_jpeg(data)
        self.assertTrue(is_valid)
        self.assertEqual(reason, "Válido")

    def test_jpeg_no_soi(self):
        """JPEG sin SOI."""
        data = b'\x00\x00\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        is_valid, reason = FileValidator.validate_jpeg(data)
        self.assertFalse(is_valid)
        self.assertIn("SOI", reason)

    def test_jpeg_no_eoi(self):
        """JPEG sin EOI."""
        data = b'\xff\xd8\xff\xe0' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_jpeg(data)
        self.assertFalse(is_valid)
        self.assertIn("EOI", reason)

    def test_jpeg_too_small(self):
        """JPEG demasiado pequeño."""
        data = b'\xff\xd8'
        is_valid, reason = FileValidator.validate_jpeg(data)
        self.assertFalse(is_valid)

    # ====================================================================
    # PNG
    # ====================================================================

    def test_png_valid(self):
        """PNG válido con IHDR e IEND."""
        ihdr = struct.pack('>I', 13) + b'IHDR' + b'\x00' * 13
        iend = struct.pack('>I', 0) + b'IEND' + b'\x00' * 4
        data = b'\x89PNG\r\n\x1a\n' + ihdr + b'\x00' * 50 + iend
        is_valid, reason = FileValidator.validate_png(data)
        self.assertTrue(is_valid)

    def test_png_no_header(self):
        """PNG sin cabecera."""
        data = b'\x00\x00\x00\x00\r\n\x1a\n' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_png(data)
        self.assertFalse(is_valid)
        self.assertIn("cabecera", reason)

    def test_png_no_ihdr(self):
        """PNG sin IHDR."""
        data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_png(data)
        self.assertFalse(is_valid)
        self.assertIn("IHDR", reason)

    # ====================================================================
    # PDF
    # ====================================================================

    def test_pdf_valid(self):
        """PDF válido."""
        data = b'%PDF-1.4' + b'\x00' * 100 + b'%%EOF'
        is_valid, reason = FileValidator.validate_pdf(data)
        self.assertTrue(is_valid)

    def test_pdf_no_header(self):
        """PDF sin cabecera."""
        data = b'\x00\x00\x00\x00' + b'\x00' * 100 + b'%%EOF'
        is_valid, reason = FileValidator.validate_pdf(data)
        self.assertFalse(is_valid)

    def test_pdf_no_eof(self):
        """PDF sin %%EOF."""
        data = b'%PDF-1.4' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_pdf(data)
        self.assertFalse(is_valid)

    # ====================================================================
    # ZIP / DOCX / XLSX / PPTX
    # ====================================================================

    def test_zip_valid(self):
        """ZIP válido con local header, central directory y EOCD."""
        data = (
            b'PK\x03\x04' +  # Local file header
            b'\x00' * 26 +    # Resto del local header
            b'PK\x01\x02' +  # Central directory
            b'\x00' * 46 +    # Resto del CD
            b'PK\x05\x06'    # End of central directory
        )
        is_valid, reason = FileValidator.validate_zip(data)
        self.assertTrue(is_valid)

    def test_zip_no_local_header(self):
        """ZIP sin local file header."""
        data = b'\x00' * 100 + b'PK\x05\x06'
        is_valid, reason = FileValidator.validate_zip(data)
        self.assertFalse(is_valid)

    def test_zip_no_eocd(self):
        """ZIP sin end of central directory."""
        data = b'PK\x03\x04' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_zip(data)
        self.assertFalse(is_valid)

    def test_docx_valid(self):
        """DOCX válido (ZIP con word/)."""
        local_header = b'PK\x03\x04' + b'\x00' * 26
        content = b'word/document.xml' + b'\x00' * 100
        eocd = b'PK\x05\x06'
        data = local_header + content + eocd
        is_valid, reason = FileValidator.validate_docx(data)
        self.assertTrue(is_valid)

    # ====================================================================
    # MP3
    # ====================================================================

    def test_mp3_with_id3(self):
        """MP3 con ID3 tag."""
        data = b'ID3' + bytes([3, 0, 0]) + b'\x00' * 100
        is_valid, reason = FileValidator.validate_mp3(data)
        self.assertTrue(is_valid)
        self.assertIn("ID3", reason)

    def test_mp3_frame_sync(self):
        """MP3 con frame sync."""
        data = b'\xff\xfb' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_mp3(data)
        self.assertTrue(is_valid)

    def test_mp3_invalid(self):
        """MP3 inválido."""
        data = b'\x00\x00\x00\x00' + b'\x00' * 100
        is_valid, reason = FileValidator.validate_mp3(data)
        self.assertFalse(is_valid)

    # ====================================================================
    # MP4
    # ====================================================================

    def test_mp4_valid(self):
        """MP4 válido con ftyp box."""
        box_size = struct.pack('>I', 20)
        data = box_size + b'ftyp' + b'isom' + b'\x00' * 8
        is_valid, reason = FileValidator.validate_mp4(data)
        self.assertTrue(is_valid)

    def test_mp4_no_ftyp(self):
        """MP4 sin ftyp."""
        data = b'\x00' * 100
        is_valid, reason = FileValidator.validate_mp4(data)
        self.assertFalse(is_valid)

    # ====================================================================
    # AVI
    # ====================================================================

    def test_avi_valid(self):
        """AVI válido."""
        data = b'RIFF' + struct.pack('<I', 100) + b'AVI ' + b'\x00' * 80
        is_valid, reason = FileValidator.validate_avi(data)
        self.assertTrue(is_valid)

    # ====================================================================
    # GIF
    # ====================================================================

    def test_gif89a_valid(self):
        """GIF89a válido."""
        data = b'GIF89a' + b'\x00' * 50 + b'\x3b'
        is_valid, reason = FileValidator.validate_gif(data)
        self.assertTrue(is_valid)

    def test_gif87a_valid(self):
        """GIF87a válido."""
        data = b'GIF87a' + b'\x00' * 50 + b'\x3b'
        is_valid, reason = FileValidator.validate_gif(data)
        self.assertTrue(is_valid)

    # ====================================================================
    # BMP
    # ====================================================================

    def test_bmp_valid(self):
        """BMP válido."""
        file_size = struct.pack('<I', 100)
        data = b'BM' + file_size + b'\x00' * 8 + b'\x00' * 80
        is_valid, reason = FileValidator.validate_bmp(data)
        self.assertTrue(is_valid)

    # ====================================================================
    # RAR
    # ====================================================================

    def test_rar_valid(self):
        """RAR válido."""
        data = b'Rar!\x1a\x07' + bytes([0x01]) + b'\x00' * 100
        is_valid, reason = FileValidator.validate_rar(data)
        self.assertTrue(is_valid)

    def test_rar_invalid_version(self):
        """RAR con versión inválida."""
        data = b'Rar!\x1a\x07' + bytes([0xFF]) + b'\x00' * 100
        is_valid, reason = FileValidator.validate_rar(data)
        self.assertFalse(is_valid)

    # ====================================================================
    # 7z
    # ====================================================================

    def test_7z_valid(self):
        """7z válido."""
        data = b'7z\xbc\xaf\x27\x1c' + b'\x00' * 50
        is_valid, reason = FileValidator.validate_7z(data)
        self.assertTrue(is_valid)

    # ====================================================================
    # GZIP
    # ====================================================================

    def test_gzip_valid(self):
        """GZIP válido."""
        data = b'\x1f\x8b\x08' + b'\x00' * 50
        is_valid, reason = FileValidator.validate_gzip(data)
        self.assertTrue(is_valid)

    # ====================================================================
    # ELF
    # ====================================================================

    def test_elf_valid(self):
        """ELF válido."""
        data = b'\x7fELF' + bytes([2, 1, 1]) + b'\x00' * 50
        is_valid, reason = FileValidator.validate_elf(data)
        self.assertTrue(is_valid)

    def test_elf_invalid_class(self):
        """ELF con clase inválida."""
        data = b'\x7fELF' + bytes([5, 1, 1]) + b'\x00' * 50
        is_valid, reason = FileValidator.validate_elf(data)
        self.assertFalse(is_valid)

    # ====================================================================
    # EXE
    # ====================================================================

    def test_exe_valid(self):
        """EXE válido con MZ."""
        pe_offset = struct.pack('<I', 64)
        data = b'MZ' + b'\x00' * 58 + pe_offset + b'\x00' * 50
        is_valid, reason = FileValidator.validate_exe(data)
        self.assertTrue(is_valid)


class TestDynamicOverlap(unittest.TestCase):
    """Tests para el overlap dinámico."""

    def test_overlap_values_are_positive(self):
        """Todos los overlaps dinámicos son positivos."""
        for sig_name, overlap in DYNAMIC_OVERLAP.items():
            self.assertGreater(overlap, 0, f"Overlap para {sig_name} debe ser > 0")

    def test_min_overlap(self):
        """Overlap mínimo global es 8KB."""
        self.assertEqual(MIN_OVERLAP, 8192)

    def test_get_dynamic_overlap(self):
        """get_dynamic_overlap retorna valor razonable."""
        overlap = get_dynamic_overlap('jpeg')
        self.assertGreaterEqual(overlap, MIN_OVERLAP)

        overlap = get_dynamic_overlap('zip')
        self.assertGreaterEqual(overlap, MIN_OVERLAP)

    def test_unknown_type_uses_min(self):
        """Tipo desconocido usa overlap mínimo."""
        overlap = get_dynamic_overlap('tipo_inexistente')
        self.assertEqual(overlap, MIN_OVERLAP)


class TestForensicEngine(unittest.TestCase):
    """Tests para el motor forense."""

    def setUp(self):
        self.engine = ForensicEngine()

    def test_find_jpeg_in_data(self):
        """Encuentra JPEG en datos."""
        # Datos con JPEG embebido
        jpeg_data = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        padding = b'\x00' * 50
        data = padding + jpeg_data + padding

        matches = self.engine.find_signatures_in_chunk(
            data, FILE_SIGNATURES, base_offset=0
        )

        # Debe encontrar al menos un JPEG
        jpeg_matches = [m for m in matches if m[0] == 'jpeg']
        self.assertGreater(len(jpeg_matches), 0)

    def test_find_multiple_files(self):
        """Encuentra múltiples archivos en datos."""
        jpeg = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        png_header = b'\x89PNG\r\n\x1a\n'
        ihdr = struct.pack('>I', 13) + b'IHDR' + b'\x00' * 13
        iend = struct.pack('>I', 0) + b'IEND' + b'\x00' * 4
        png = png_header + ihdr + b'\x00' * 50 + iend

        data = b'\x00' * 50 + jpeg + b'\x00' * 50 + png

        matches = self.engine.find_signatures_in_chunk(
            data, FILE_SIGNATURES, base_offset=0
        )

        types_found = set(m[0] for m in matches)
        self.assertIn('jpeg', types_found)

    def test_deduplicate(self):
        """Deduplicación funciona correctamente."""
        candidate1 = FileCandidate(
            sig_name='jpeg', ext='.jpg',
            offset=0, size=100, data=b'\xff\xd8' + b'\x00' * 98 + b'\xff\xd9'
        )
        candidate2 = FileCandidate(
            sig_name='jpeg', ext='.jpg',
            offset=200, size=100, data=b'\xff\xd8' + b'\x00' * 98 + b'\xff\xd9'
        )

        # Primero no es duplicado
        self.assertFalse(self.engine.deduplicate(candidate1))
        # Segundo es duplicado (mismos datos)
        self.assertTrue(self.engine.deduplicate(candidate2))

    def test_is_all_zeros(self):
        """Detección de datos todo ceros."""
        self.assertTrue(ForensicEngine._is_all_zeros(b'\x00' * 1000))
        self.assertFalse(ForensicEngine._is_all_zeros(b'\x00' * 500 + b'\x01' + b'\x00' * 499))

    def test_check_minimum_size(self):
        """Verificación de tamaño mínimo."""
        self.assertTrue(ForensicEngine._check_minimum_size(b'\x00' * 200, '.jpg'))
        self.assertFalse(ForensicEngine._check_minimum_size(b'\x00' * 10, '.jpg'))


class TestFileCandidate(unittest.TestCase):
    """Tests para FileCandidate."""

    def test_hash_computed(self):
        """Hash se calcula automáticamente."""
        data = b'\xff\xd8' + b'\x00' * 100 + b'\xff\xd9'
        candidate = FileCandidate(
            sig_name='jpeg', ext='.jpg',
            offset=0, size=len(data), data=data
        )
        self.assertNotEqual(candidate.hash, '')
        self.assertEqual(len(candidate.hash), 32)  # MD5 hex

    def test_same_data_same_hash(self):
        """Mismos datos producen mismo hash."""
        data = b'\xff\xd8' + b'\x00' * 100 + b'\xff\xd9'
        c1 = FileCandidate(sig_name='jpeg', ext='.jpg', offset=0, size=len(data), data=data)
        c2 = FileCandidate(sig_name='jpeg', ext='.jpg', offset=100, size=len(data), data=data)
        self.assertEqual(c1.hash, c2.hash)

    def test_different_data_different_hash(self):
        """Datos diferentes producen hashes diferentes."""
        c1 = FileCandidate(sig_name='jpeg', ext='.jpg', offset=0, size=100, data=b'\x01' * 100)
        c2 = FileCandidate(sig_name='jpeg', ext='.jpg', offset=0, size=100, data=b'\x02' * 100)
        self.assertNotEqual(c1.hash, c2.hash)


class TestForensicScanCoordinator(unittest.TestCase):
    """Tests para el coordinador de escaneo."""

    def setUp(self):
        self.coordinator = ForensicScanCoordinator(chunk_size=1024 * 1024)

    def test_scan_empty_data(self):
        """Escaneo de datos vacíos."""
        results = self.coordinator.scan_chunk(
            data=b'\x00' * 1024,
            base_offset=0,
            signatures=FILE_SIGNATURES,
            total_device_size=1024 * 1024,
        )
        self.assertEqual(len(results), 0)

    def test_scan_with_jpeg(self):
        """Escaneo con JPEG embebido."""
        jpeg = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        data = b'\x00' * 50 + jpeg + b'\x00' * 50

        results = self.coordinator.scan_chunk(
            data=data,
            base_offset=0,
            signatures=FILE_SIGNATURES,
            total_device_size=1024 * 1024,
        )

        # Puede o no encontrar el JPEG dependiendo del tamaño mínimo
        # El test verifica que no crashea
        self.assertIsInstance(results, list)


class TestFastHash(unittest.TestCase):
    """Tests para fast_hash."""

    def test_small_data(self):
        """Hash de datos pequeños."""
        data = b'hello world'
        h = fast_hash(data)
        self.assertEqual(len(h), 32)  # MD5 hex

    def test_large_data(self):
        """Hash de datos grandes (usa muestra)."""
        data = b'\x00' * (100 * 1024)  # 100KB
        h = fast_hash(data)
        self.assertEqual(len(h), 32)

    def test_same_data_same_hash(self):
        """Mismos datos = mismo hash."""
        data = b'test data for hashing'
        self.assertEqual(fast_hash(data), fast_hash(data))


if __name__ == '__main__':
    unittest.main()
