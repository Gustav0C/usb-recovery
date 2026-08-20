"""
Firmas de archivos (Magic Bytes) para file carving.
"""

from typing import Dict

FILE_SIGNATURES: Dict[str, Dict] = {
    # Imágenes
    "jpeg": {
        "header": b'\xff\xd8\xff\xe0',
        "header2": b'\xff\xd8\xff\xe1',
        "footer": b'\xff\xd9',
        "max_size": 25 * 1024 * 1024,  # 25 MB
        "ext": ".jpg"
    },
    "png": {
        "header": b'\x89PNG\r\n\x1a\n',
        "footer": b'\x00\x00\x00\x00IEND\xae\x42\x60\x82',
        "max_size": 50 * 1024 * 1024,  # 50 MB
        "ext": ".png"
    },
    "gif87": {
        "header": b'GIF87a',
        "footer": b'\x00;',
        "max_size": 10 * 1024 * 1024,
        "ext": ".gif"
    },
    "gif89": {
        "header": b'GIF89a',
        "footer": b'\x00;',
        "max_size": 10 * 1024 * 1024,
        "ext": ".gif"
    },
    "bmp": {
        "header": b'BM',
        "footer": None,
        "max_size": 50 * 1024 * 1024,
        "ext": ".bmp"
    },
    "tiff": {
        "header": b'II\x2a\x00',
        "header2": b'MM\x00\x2a',
        "footer": None,
        "max_size": 100 * 1024 * 1024,
        "ext": ".tiff"
    },
    "webp": {
        "header": b'RIFF',
        "check_offset": 8,
        "check_bytes": b'WEBP',
        "footer": None,
        "max_size": 50 * 1024 * 1024,
        "ext": ".webp"
    },
    
    # Documentos
    "pdf": {
        "header": b'%PDF',
        "footer": b'%%EOF',
        "max_size": 200 * 1024 * 1024,
        "ext": ".pdf"
    },
    "docx": {
        "header": b'PK\x03\x04',
        "check_content": b'word/',
        "footer": None,
        "max_size": 200 * 1024 * 1024,
        "ext": ".docx"
    },
    "xlsx": {
        "header": b'PK\x03\x04',
        "check_content": b'xl/',
        "footer": None,
        "max_size": 200 * 1024 * 1024,
        "ext": ".xlsx"
    },
    "pptx": {
        "header": b'PK\x03\x04',
        "check_content": b'ppt/',
        "footer": None,
        "max_size": 200 * 1024 * 1024,
        "ext": ".pptx"
    },
    
    # Comprimidos
    "zip": {
        "header": b'PK\x03\x04',
        "footer": b'PK\x05\x06',
        "max_size": 500 * 1024 * 1024,
        "ext": ".zip"
    },
    "rar": {
        "header": b'Rar!\x1a\x07',
        "footer": None,
        "max_size": 500 * 1024 * 1024,
        "ext": ".rar"
    },
    "7z": {
        "header": b'7z\xbc\xaf\x27\x1c',
        "footer": None,
        "max_size": 500 * 1024 * 1024,
        "ext": ".7z"
    },
    "gzip": {
        "header": b'\x1f\x8b\x08',
        "footer": None,
        "max_size": 500 * 1024 * 1024,
        "ext": ".gz"
    },
    
    # Audio/Video
    "mp3": {
        "header": b'\xff\xfb',
        "header2": b'ID3',
        "footer": None,
        "max_size": 100 * 1024 * 1024,
        "ext": ".mp3"
    },
    "mp4": {
        "header": b'\x00\x00\x00',
        "check_offset": 4,
        "check_bytes": b'ftyp',
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
        "ext": ".mp4"
    },
    "avi": {
        "header": b'RIFF',
        "check_offset": 8,
        "check_bytes": b'AVI ',
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
        "ext": ".avi"
    },
    "mkv": {
        "header": b'\x1a\x45\xdf\xa3',
        "footer": None,
        "max_size": 2 * 1024 * 1024 * 1024,
        "ext": ".mkv"
    },
    "wav": {
        "header": b'RIFF',
        "check_offset": 8,
        "check_bytes": b'WAVE',
        "footer": None,
        "max_size": 500 * 1024 * 1024,
        "ext": ".wav"
    },
    
    # Ejecutables y otros
    "exe": {
        "header": b'MZ',
        "footer": None,
        "max_size": 200 * 1024 * 1024,
        "ext": ".exe"
    },
    "elf": {
        "header": b'\x7fELF',
        "footer": None,
        "max_size": 200 * 1024 * 1024,
        "ext": ".elf"
    },
}
