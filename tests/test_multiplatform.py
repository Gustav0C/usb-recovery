"""
Tests para el modulo multiplataforma.
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from usb_recovery.platform.detector import (
    DeviceInfo, DeviceDetector, WindowsDetector,
    LinuxDetector, DarwinDetector, get_detector,
)


class TestDeviceInfo(unittest.TestCase):
    """Tests para la dataclass DeviceInfo."""

    def test_basic_properties(self):
        dev = DeviceInfo(
            id='E', name='USB', path='\\\\.\\E:',
            filesystem='FAT32', total_size=8*1024**3,
            free_size=4*1024**3, is_removable=True,
        )
        self.assertEqual(dev.used_size, 4*1024**3)
        self.assertAlmostEqual(dev.used_percent, 50.0, places=1)
        self.assertAlmostEqual(dev.size_gb, 8.0, places=1)
        self.assertAlmostEqual(dev.free_gb, 4.0, places=1)

    def test_zero_total(self):
        dev = DeviceInfo(
            id='X', name='Empty', path='/dev/X',
            filesystem='', total_size=0, free_size=0,
            is_removable=True,
        )
        self.assertEqual(dev.used_percent, 0.0)

    def test_model_serial(self):
        dev = DeviceInfo(
            id='sdb', name='USB', path='/dev/sdb',
            filesystem='exFAT', total_size=32*1024**3,
            free_size=16*1024**3, is_removable=True,
            model='SanDisk Ultra', serial='ABC123',
        )
        self.assertEqual(dev.model, 'SanDisk Ultra')
        self.assertEqual(dev.serial, 'ABC123')


class TestLinuxDetector(unittest.TestCase):
    """Tests para LinuxDetector con mocks."""

    def test_check_sys_removable_true(self):
        detector = LinuxDetector()
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read.return_value = '1\n'
            self.assertTrue(detector._check_sys_removable('sdb'))

    def test_check_sys_removable_false(self):
        detector = LinuxDetector()
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read.return_value = '0\n'
            self.assertFalse(detector._check_sys_removable('sda'))

    def test_check_sys_removable_file_not_found(self):
        detector = LinuxDetector()
        with patch('builtins.open', side_effect=FileNotFoundError):
            self.assertFalse(detector._check_sys_removable('sda'))

    def test_get_raw_path(self):
        detector = LinuxDetector()
        self.assertEqual(detector.get_raw_path('sdb'), '/dev/sdb')
        self.assertEqual(detector.get_raw_path('/dev/sdc'), '/dev/sdc')

    @patch('subprocess.run')
    def test_list_with_lsblk(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"blockdevices":[{"name":"sdb","size":34359738368,'
                   '"fstype":"exfat","mountpoint":"/media/usb","rm":true,'
                   '"model":"SanDisk Ultra","serial":"ABC123","tran":"usb"}]}',
        )
        detector = LinuxDetector()
        devices = detector._list_with_lsblk()
        self.assertGreater(len(devices), 0)
        self.assertEqual(devices[0].id, 'sdb')

    @patch('subprocess.run')
    def test_list_with_lsblk_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='lsblk', timeout=5)
        detector = LinuxDetector()
        devices = detector._list_with_lsblk()
        self.assertEqual(len(devices), 0)


class TestDarwinDetector(unittest.TestCase):
    """Tests para DarwinDetector con mocks."""

    def test_get_raw_path(self):
        detector = DarwinDetector()
        self.assertEqual(detector.get_raw_path('disk2'), '/dev/disk2')


class TestWindowsDetector(unittest.TestCase):
    """Tests para WindowsDetector."""

    def test_get_raw_path(self):
        detector = WindowsDetector()
        self.assertEqual(detector.get_raw_path('E'), '\\\\.\\E:')
        self.assertEqual(detector.get_raw_path('e'), '\\\\.\\E:')


class TestGetDetector(unittest.TestCase):
    """Tests para la factory get_detector."""

    def test_returns_device_detector(self):
        detector = get_detector()
        self.assertIsInstance(detector, DeviceDetector)

    def test_returns_correct_platform(self):
        detector = get_detector()
        if sys.platform == 'win32':
            self.assertIsInstance(detector, WindowsDetector)
        elif sys.platform == 'darwin':
            self.assertIsInstance(detector, DarwinDetector)
        elif sys.platform.startswith('linux'):
            self.assertIsInstance(detector, LinuxDetector)


if __name__ == '__main__':
    unittest.main()
