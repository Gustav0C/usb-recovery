"""
Tests para features avanzadas.
"""

import unittest
import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from usb_recovery.core.advanced import (
    ForensicMode, AuditEntry, ForensicReport,
    ScanFilter, ExportManager, ForensicAnalyzer,
)


class TestForensicMode(unittest.TestCase):
    """Tests para el modo forense."""

    def setUp(self):
        self.fm = ForensicMode(case_id='TEST-001', examiner='Test User')

    def test_init(self):
        self.assertEqual(self.fm.case_id, 'TEST-001')
        self.assertEqual(self.fm.examiner, 'Test User')
        self.assertEqual(len(self.fm.audit_log), 0)

    def test_log_access(self):
        self.fm.log_access('/dev/sdb', 'scan_start', 'Beginning scan')
        self.assertEqual(len(self.fm.audit_log), 1)
        self.assertEqual(self.fm.audit_log[0].action, 'scan_start')

    def test_generate_report(self):
        self.fm.log_access('/dev/sdb', 'scan_start')
        report = self.fm.generate_report(
            device_path='/dev/sdb',
            device_info={'size': 8*1024**3},
            recovered_files=[{'type': 'jpeg', 'size': 1024}],
        )
        self.assertIsInstance(report, ForensicReport)
        self.assertEqual(report.files_found, 1)

    def test_export_report(self):
        report = self.fm.generate_report(
            device_path='/dev/sdb',
            device_info={},
            recovered_files=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.fm.export_report(report, tmpdir)
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data['case_id'], 'TEST-001')


class TestScanFilter(unittest.TestCase):
    """Tests para el filtrado de resultados."""

    def setUp(self):
        self.results = [
            {'type': 'jpeg', 'ext': '.jpg', 'size': 5000, 'offset': 1000, 'hash': 'abc123'},
            {'type': 'pdf', 'ext': '.pdf', 'size': 2000, 'offset': 6000, 'hash': 'def456'},
            {'type': 'jpeg', 'ext': '.jpg', 'size': 8000, 'offset': 8000, 'hash': 'abc123'},
            {'type': 'png', 'ext': '.png', 'size': 3000, 'offset': 16000, 'hash': 'ghi789'},
        ]

    def test_no_filter(self):
        f = ScanFilter(self.results)
        self.assertEqual(len(f.get_results()), 4)

    def test_filter_by_type(self):
        f = ScanFilter(self.results)
        f.filter_by_type(['jpeg'])
        self.assertEqual(len(f.get_results()), 2)

    def test_filter_by_size(self):
        f = ScanFilter(self.results)
        f.filter_by_size(min_size=3000, max_size=6000)
        self.assertEqual(len(f.get_results()), 2)

    def test_filter_by_offset(self):
        f = ScanFilter(self.results)
        f.filter_by_offset(start=0, end=7000)
        self.assertEqual(len(f.get_results()), 2)

    def test_exclude_duplicates(self):
        f = ScanFilter(self.results)
        f.exclude_duplicates()
        self.assertEqual(len(f.get_results()), 3)

    def test_chain_filters(self):
        f = ScanFilter(self.results)
        f.filter_by_type(['jpeg']).filter_by_size(min_size=4000)
        self.assertEqual(len(f.get_results()), 2)

    def test_get_stats(self):
        f = ScanFilter(self.results)
        stats = f.get_stats()
        self.assertEqual(stats['count'], 4)
        self.assertEqual(stats['by_type']['jpeg'], 2)


class TestExportManager(unittest.TestCase):
    """Tests para la exportación."""

    def setUp(self):
        self.results = [
            {'type': 'jpeg', 'ext': '.jpg', 'size': 5000, 'offset': 1000},
            {'type': 'pdf', 'ext': '.pdf', 'size': 2000, 'offset': 6000},
        ]
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_export_json(self):
        exporter = ExportManager(self.results, self.tmpdir)
        path = exporter.export_json()
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(data['total_files'], 2)

    def test_export_csv(self):
        exporter = ExportManager(self.results, self.tmpdir)
        path = exporter.export_csv()
        self.assertTrue(os.path.exists(path))

    def test_export_html(self):
        exporter = ExportManager(self.results, self.tmpdir)
        path = exporter.export_html()
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn('USB Recovery Report', content)

    def test_export_metadata_only(self):
        exporter = ExportManager(self.results, self.tmpdir)
        path = exporter.export_metadata_only()
        self.assertTrue(os.path.exists(path))


class TestForensicAnalyzer(unittest.TestCase):
    """Tests para el análisis forense."""

    def setUp(self):
        self.results = [
            {'type': 'jpeg', 'size': 5000, 'offset': 1000, 'fragmented': False},
            {'type': 'pdf', 'size': 2000, 'offset': 6000, 'fragmented': True},
            {'type': 'png', 'size': 3000, 'offset': 8000, 'fragmented': False},
        ]
        self.analyzer = ForensicAnalyzer(self.results, device_size=100*1024*1024)

    def test_analyze_fragmentation(self):
        frag = self.analyzer.analyze_fragmentation()
        self.assertEqual(frag['total_files'], 3)
        self.assertEqual(frag['fragmented'], 1)
        self.assertEqual(frag['contiguous'], 2)

    def test_analyze_distribution(self):
        dist = self.analyzer.analyze_distribution()
        self.assertEqual(dist['device_size'], 100*1024*1024)
        self.assertEqual(len(dist['zones']), 10)

    def test_generate_summary(self):
        summary = self.analyzer.generate_summary()
        self.assertEqual(summary['total_files'], 3)
        self.assertIn('fragmentation', summary)
        self.assertIn('integrity_estimate', summary)


if __name__ == '__main__':
    unittest.main()
