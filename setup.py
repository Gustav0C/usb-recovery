"""
USB Recovery Tool - Setup para PyPI
"""

from setuptools import setup, find_packages
from pathlib import Path

# Leer README
readme_path = Path(__file__).parent / 'README.md'
long_description = readme_path.read_text(encoding='utf-8') if readme_path.exists() else ''

setup(
    name='usb-recovery-pro',
    version='2.0.0',
    description='Professional USB file recovery tool with forensic engine and performance optimizations',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Gustav0C',
    author_email='gcanales58@gmail.com',
    url='https://github.com/Gustav0C/usb-recovery',
    license='MIT',
    python_requires='>=3.7',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'usb-recovery=usb_recovery.main:main',
            'usb-recovery-tui=usb_recovery_tui:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: System :: Filesystems',
        'Topic :: Security :: Forensics',
        'Topic :: Utilities :: File Systems',
        'Natural Language :: English',
        'Natural Language :: Spanish',
    ],
    keywords='usb recovery forensics file-carving data-recovery deleted-files',
    project_urls={
        'Bug Reports': 'https://github.com/Gustav0C/usb-recovery/issues',
        'Source': 'https://github.com/Gustav0C/usb-recovery',
        'Documentation': 'https://github.com/Gustav0C/usb-recovery#readme',
    },
)
