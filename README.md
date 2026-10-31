# USB Recovery Pro

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

Professional USB file recovery tool with forensic engine, performance optimizations, and advanced analysis capabilities.

<img width="753" height="395" alt="Portafolioimage" src="https://github.com/user-attachments/assets/738779af-fa60-489d-909f-eacdf31859a0" />

## Features

- **File Carving Engine**: Scan raw device sectors to recover deleted files
- **Forensic Analysis**: Chain of custody, integrity verification, fragmentation detection
- **20+ File Types**: JPEG, PNG, PDF, DOCX, ZIP, MP3, MP4, and more
- **Performance Optimized**: Multi-pattern search, native I/O, parallel scanning
- **Cross-Platform**: Windows, Linux, and macOS support
- **Professional Export**: JSON, CSV, HTML reports, ZIP archives

## Quick Start

### Installation

```bash
# From PyPI (when published)
pip install usb-recovery-pro

# From source
git clone https://github.com/Gustav0C/usb-recovery.git
cd usb-recovery
pip install -e .
```

### Basic Usage

```bash
# List connected USB devices
usb-recovery --list-devices

# Recover all files from a device
usb-recovery --device \\.\E: --output ./recovered

# Recover only specific types
usb-recovery --device \\.\E: --output ./recovered --types jpeg,pdf,png

# Scan first 1GB only
usb-recovery --device \\.\E: --output ./recovered --size 1GB
```

### Interactive TUI

```bash
# Launch the terminal user interface
usb-recovery-tui
```

## Supported File Types

| Category | Types |
|----------|-------|
| **Images** | JPEG, PNG, GIF, BMP, TIFF, WebP |
| **Documents** | PDF, DOCX, XLSX, PPTX |
| **Archives** | ZIP, RAR, 7z, GZIP |
| **Audio** | MP3, WAV |
| **Video** | MP4, AVI, MKV |
| **Executables** | EXE, ELF |

## Advanced Features

### Forensic Mode

```python
from usb_recovery import ForensicMode

# Initialize forensic mode with case tracking
forensic = ForensicMode(case_id="CASE-2024-001", examiner="John Doe")

# Log all actions for chain of custody
forensic.log_access("/dev/sdb", "scan_start", "Initial scan")

# Generate forensic report
report = forensic.generate_report(
    device_path="/dev/sdb",
    device_info={"size": 8*1024**3},
    recovered_files=results
)
forensic.export_report(report, "./output")
```

### Post-Scan Filtering

```python
from usb_recovery import ScanFilter

# Filter results by multiple criteria
filtered = (ScanFilter(results)
    .filter_by_type(['jpeg', 'png'])
    .filter_by_size(min_size=1024, max_size=10*1024*1024)
    .exclude_duplicates()
    .get_results())
```

### Export Results

```python
from usb_recovery import ExportManager

exporter = ExportManager(results, "./output")

# Export to multiple formats
exporter.export_json("results.json")
exporter.export_csv("results.csv")
exporter.export_html("report.html")  # Visual HTML report
exporter.export_to_zip("./recovered_files")  # Compress recovered files
```

### Forensic Analysis

```python
from usb_recovery import ForensicAnalyzer

analyzer = ForensicAnalyzer(results, device_size=8*1024**3)

# Get detailed analysis
summary = analyzer.generate_summary()
print(f"Fragmentation rate: {summary['fragmentation']['fragmentation_rate']:.1%}")
print(f"Integrity score: {summary['integrity_estimate']['grade']}")
```

## Architecture

```
usb_recovery/
├── core/
│   ├── carver.py          # Main carving engine
│   ├── forensic.py        # Forensic analysis engine
│   ├── validator.py       # File integrity validation
│   ├── deduplicator.py    # Hash-based deduplication
│   ├── performance.py     # Multi-pattern search, native I/O
│   ├── advanced.py        # Forensic mode, filtering, export
│   └── signatures.py      # File type signatures (20+ formats)
├── platform/
│   └── detector.py        # Cross-platform device detection
├── utils/
│   ├── config.py          # Scan configuration
│   ├── logging.py         # JSON logging
│   └── progress.py        # Progress bar with ETA
└── main.py                # CLI entry point
```

## Performance

- **Multi-pattern search**: First-byte index skips 99% of positions
- **Native I/O**: Windows NO_BUFFERING, Linux O_DIRECT
- **Parallel scanning**: ProcessPoolExecutor for multi-core
- **Offset cache**: Persistent cache for rescan optimization

## Command Line Options

```
--device, -d           Device path (e.g., \\.\E: or /dev/sdb)
--output, -o           Output directory (default: ./recovered)
--list-devices, -l     List connected USB devices
--types, -t            File types to search (comma-separated)
--offset               Scan start offset in bytes
--size, -s             Maximum scan size (e.g., 1GB, 500MB)
--chunk-size           Read block size (default: 1MB)
```

## Platform Support

| Platform | Device Detection | Native I/O | Status |
|----------|-----------------|------------|--------|
| Windows | Win32 API | CreateFile NO_BUFFERING | Full |
| Linux | lsblk + /sys/block | O_DIRECT | Full |
| macOS | diskutil | Standard | Full |

## How It Works

1. **Raw Access**: Opens device at sector level (requires admin/root)
2. **Signature Scan**: Searches for file type headers (JPEG: FFD8FF, PDF: %PDF-, etc.)
3. **Boundary Detection**: Finds file endings (JPEG: FFD9, PDF: %%EOF)
4. **Validation**: Verifies file integrity using format-specific checks
5. **Recovery**: Saves validated files with deduplication

## Limitations

- Cannot recover original filenames or folder structure
- Fragmented files may be partially recovered
- Files < 100 bytes are skipped (false positive prevention)
- Encrypted volumes (BitLocker, VeraCrypt) not supported
- Requires admin/root for raw device access

## Tips for Best Results

1. **Act quickly**: Deleted data gets overwritten over time
2. **Don't write to the USB**: Avoid using the device after deletion
3. **Run as administrator**: Required for raw device access
4. **Use type filters**: If only looking for photos, use `--types jpeg,png`
5. **Check manually**: Some recovered files may be corrupted

## Development

```bash
# Clone repository
git clone https://github.com/Gustav0C/usb-recovery.git
cd usb-recovery

# Install in development mode
pip install -e .

# Run tests
python -m unittest discover tests/

# Run specific test suite
python -m unittest tests.test_forensic
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

Use this tool responsibly and only on devices you own or have authorization to recover data from. The authors are not responsible for any misuse.

---

**Built with Python** | **No external dependencies** | **Cross-platform**
