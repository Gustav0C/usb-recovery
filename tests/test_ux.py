"""
Tests para UX/UI y utilidades.
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from usb_recovery.utils.progress import ProgressBar
from usb_recovery_tui import Colors


class TestProgressBar(unittest.TestCase):
    """Tests para la barra de progreso."""

    def test_init(self):
        bar = ProgressBar(100, prefix='Test: ')
        self.assertEqual(bar.total, 100)
        self.assertEqual(bar.current, 0)
        self.assertEqual(bar.found, 0)

    def test_update(self):
        bar = ProgressBar(100)
        bar.update(10)
        self.assertEqual(bar.current, 10)

    def test_update_with_found(self):
        bar = ProgressBar(100)
        bar.update(10, found=2)
        self.assertEqual(bar.current, 10)
        self.assertEqual(bar.found, 2)

    def test_finish(self):
        bar = ProgressBar(100)
        bar.update(50)
        # Mock stdout to avoid encoding issues
        with patch('sys.stdout', new_callable=StringIO):
            bar.finish()
        self.assertEqual(bar.current, 100)

    def test_format_time_seconds(self):
        bar = ProgressBar(100)
        self.assertEqual(bar._format_time(45), '00:45')

    def test_format_time_minutes(self):
        bar = ProgressBar(100)
        self.assertEqual(bar._format_time(125), '02:05')

    def test_format_time_hours(self):
        bar = ProgressBar(100)
        self.assertEqual(bar._format_time(3661), '01:01:01')

    def test_format_time_negative(self):
        bar = ProgressBar(100)
        self.assertEqual(bar._format_time(-10), '--:--')

    def test_zero_total(self):
        bar = ProgressBar(0)
        with patch('sys.stdout', new_callable=StringIO):
            bar._print()  # Should not raise


class TestColors(unittest.TestCase):
    """Tests para la clase Colors."""

    def test_color_codes_exist(self):
        self.assertIsInstance(Colors.RESET, str)
        self.assertIsInstance(Colors.BOLD, str)
        self.assertIsInstance(Colors.GREEN, str)
        self.assertIsInstance(Colors.RED, str)

    def test_supports_color(self):
        # Should not raise
        result = Colors.supports_color()
        self.assertIsInstance(result, bool)


class TestTerminalUtils(unittest.TestCase):
    """Tests para utilidades de terminal."""

    def test_print_centered(self):
        # Should not raise
        with patch('sys.stdout', new_callable=StringIO):
            from usb_recovery_tui import print_centered
            print_centered("Test", 40, Colors.GREEN)

    def test_print_centered_no_color(self):
        with patch('sys.stdout', new_callable=StringIO):
            from usb_recovery_tui import print_centered
            print_centered("Test", 40)

    def test_print_separator(self):
        with patch('sys.stdout', new_callable=StringIO):
            from usb_recovery_tui import print_separator
            print_separator(40, '-')

    def test_print_box_single_line(self):
        with patch('sys.stdout', new_callable=StringIO):
            from usb_recovery_tui import print_box
            print_box(["Hello"], 40, "Title")

    def test_print_box_empty(self):
        with patch('sys.stdout', new_callable=StringIO):
            from usb_recovery_tui import print_box
            print_box([], 40, "Empty")

    def test_print_box_long_line_truncation(self):
        # Should truncate long lines
        with patch('sys.stdout', new_callable=StringIO):
            from usb_recovery_tui import print_box
            long_line = "A" * 100
            print_box([long_line], 40)


if __name__ == '__main__':
    unittest.main()
