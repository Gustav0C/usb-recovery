"""
USB Recovery Tool - Setup
"""

from setuptools import setup, find_packages
from pathlib import Path

# Leer README
readme_path = Path(__file__).parent / 'README.md'
long_description = readme_path.read_text(encoding='utf-8') if readme_path.exists() else ''

setup(
    name='usb-recovery',
    version='2.0.0',
    description='Herramienta de recuperación de archivos eliminados de USB',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='USB Recovery Team',
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
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: System :: Filesystems',
        'Topic :: Security',
    ],
)
