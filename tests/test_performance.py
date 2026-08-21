"""
Tests unitarios para el modulo de rendimiento.
"""

import unittest
import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from usb_recovery.core.performance import (
    MultiPatternSearcher, SignatureIndex,
    OffsetCache, StandardDeviceReader,
)
from usb_recovery.core.signatures import FILE_SIGNATURES


class TestMultiPatternSearcher(unittest.TestCase):
    """Tests para la busqueda multi-patron."""

    def setUp(self):
        self.searcher = MultiPatternSearcher(FILE_SIGNATURES)

    def test_index_has_entries(self):
        self.assertGreater(len(self.searcher.index.first_bytes), 0)

    def test_find_jpeg(self):
        jpeg = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        data = b'\x00' * 50 + jpeg
        matches = self.searcher.search(data, base_offset=0)
        types = [m[0] for m in matches]
        self.assertIn('jpeg', types)

    def test_find_png(self):
        ihdr = b'\x00\x00\x00\x0dIHDR' + b'\x00' * 13
        iend = b'\x00\x00\x00\x00IEND' + b'\x00' * 4
        png = b'\x89PNG\r\n\x1a\n' + ihdr + b'\x00' * 50 + iend
        matches = self.searcher.search(png, base_offset=100)
        types = [m[0] for m in matches]
        self.assertIn('png', types)

    def test_find_pdf(self):
        pdf = b'%PDF-1.4' + b'\x00' * 100 + b'%%EOF'
        matches = self.searcher.search(pdf, base_offset=0)
        types = [m[0] for m in matches]
        self.assertIn('pdf', types)

    def test_find_zip(self):
        zip_data = b'PK\x03\x04' + b'\x00' * 26 + b'PK\x01\x02' + b'\x00' * 46 + b'PK\x05\x06'
        matches = self.searcher.search(zip_data, base_offset=0)
        types = [m[0] for m in matches]
        self.assertIn('zip', types)

    def test_find_mp3_id3(self):
        mp3 = b'ID3' + bytes([3, 0, 0]) + b'\x00' * 100
        matches = self.searcher.search(mp3, base_offset=0)
        types = [m[0] for m in matches]
        self.assertIn('mp3', types)

    def test_find_mp3_frame(self):
        mp3 = b'\xff\xfb' + b'\x00' * 100
        matches = self.searcher.search(mp3, base_offset=0)
        types = [m[0] for m in matches]
        self.assertIn('mp3', types)

    def test_find_multiple(self):
        jpeg = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        pdf = b'%PDF-1.4' + b'\x00' * 50 + b'%%EOF'
        data = b'\x00' * 20 + jpeg + b'\x00' * 20 + pdf
        matches = self.searcher.search(data, base_offset=0)
        types = set(m[0] for m in matches)
        self.assertIn('jpeg', types)
        self.assertIn('pdf', types)

    def test_base_offset(self):
        jpeg = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'\xff\xd9'
        data = b'\x00' * 50 + jpeg
        matches = self.searcher.search(data, base_offset=1000)
        for sig_name, offset in matches:
            if sig_name == 'jpeg':
                self.assertGreaterEqual(offset, 1050)

    def test_empty_data(self):
        matches = self.searcher.search(b'', base_offset=0)
        self.assertEqual(len(matches), 0)

    def test_no_false_positives(self):
        data = b'\x01\x02\x03\x04' * 1000
        matches = self.searcher.search(data, base_offset=0)
        self.assertLess(len(matches), 5)

    def test_verify_secondary_check_bytes(self):
        webp = b'RIFF' + b'\x00' * 4 + b'WEBP' + b'\x00' * 100
        matches = self.searcher.search(webp, base_offset=0)
        types = [m[0] for m in matches]
        self.assertIn('webp', types)


class TestOffsetCache(unittest.TestCase):
    """Tests para la cache de offsets."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache = OffsetCache(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_empty_cache(self):
        self.assertEqual(self.cache.get_file_count(), 0)

    def test_add_result(self):
        self.cache.add_result('jpeg', 1000, 5000, 'abc123')
        self.cache.add_result('pdf', 6000, 2000, 'def456')
        self.assertEqual(self.cache.get_file_count(), 2)

    def test_scanned_ranges(self):
        self.cache.add_result('jpeg', 1000, 5000, 'abc123')
        self.cache.add_result('pdf', 6000, 2000, 'def456')
        ranges = self.cache.get_scanned_ranges()
        self.assertEqual(len(ranges), 2)

    def test_save_and_load(self):
        self.cache.add_result('jpeg', 1000, 5000, 'abc123')
        self.cache.save()
        cache2 = OffsetCache(self.test_dir)
        self.assertEqual(cache2.get_file_count(), 1)

    def test_clear(self):
        self.cache.add_result('jpeg', 1000, 5000, 'abc123')
        self.cache.save()
        self.cache.clear()
        self.assertEqual(self.cache.get_file_count(), 0)


class TestSignatureIndex(unittest.TestCase):
    """Tests para el indice de firmas."""

    def test_index_construction(self):
        sigs = {'jpeg': FILE_SIGNATURES['jpeg']}
        searcher = MultiPatternSearcher(sigs)
        self.assertIn(0xFF, searcher.index.first_bytes)

    def test_multiple_headers_indexed(self):
        searcher = MultiPatternSearcher(FILE_SIGNATURES)
        jpeg_entries = searcher.index.first_byte_map.get(0xFF, [])
        jpeg_names = [name for name, _ in jpeg_entries]
        self.assertIn('jpeg', jpeg_names)


if __name__ == '__main__':
    unittest.main()
