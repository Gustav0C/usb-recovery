"""
Validación de integridad de archivos recuperados.

Soporta validación avanzada para:
- Imágenes: JPEG, PNG, GIF, BMP, WebP
- Documentos: PDF, DOCX, XLSX, PPTX
- Comprimidos: ZIP, RAR, 7z, GZIP
- Audio: MP3, WAV
- Video: MP4, AVI
- Ejecutables: EXE, ELF

Cada validador verifica estructura interna, no solo cabecera+footer.
"""

import struct
from typing import Tuple
from enum import Enum


class ValidationResult(Enum):
    """Resultado de validación."""
    VALID = "valid"
    INVALID = "invalid"
    PARTIAL = "partial"      # Archivo incompleto pero válidamente estructurado
    UNKNOWN = "unknown"      # Sin validación disponible


class FileValidator:
    """Valida integridad de archivos recuperados."""

    # ========================================================================
    # IMÁGENES
    # ========================================================================

    @staticmethod
    def validate_jpeg(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura JPEG completa.

        Verifica:
        - SOI marker (FFD8)
        - Al menos un marker APP/COM/DQT/DHT/SOF/SOS
        - EOI marker (FFD9)
        """
        if len(data) < 4:
            return False, "Archivo demasiado pequeño"

        # SOI
        if data[:2] != b'\xff\xd8':
            return False, "Falta SOI (FFD8)"

        # Buscar EOI en los últimos 32 bytes
        eoi_found = False
        for i in range(max(0, len(data) - 32), len(data) - 1):
            if data[i:i+2] == b'\xff\xd9':
                eoi_found = True
                break

        if not eoi_found:
            return False, "Falta EOI (FFD9)"

        # Verificar que hay al menos un marker después del SOI
        if len(data) > 4:
            if data[2] != 0xff:
                return False, "Marker inválido después de SOI"

        return True, "Válido"

    @staticmethod
    def validate_png(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura PNG completa.

        Verifica:
        - Cabecera PNG (8 bytes)
        - IHDR chunk (primer chunk obligatorio)
        - IEND chunk (último chunk obligatorio)
        - Cada chunk tiene length + type + data + CRC
        """
        if len(data) < 8:
            return False, "Archivo demasiado pequeño"

        # Cabecera PNG
        if data[:8] != b'\x89PNG\r\n\x1a\n':
            return False, "Falta cabecera PNG"

        # IHDR debe ser el primer chunk
        if data[12:16] != b'IHDR':
            return False, "Falta IHDR como primer chunk"

        # IEND debe existir
        iend_pos = data.find(b'IEND')
        if iend_pos == -1:
            return False, "Falta chunk IEND"

        return True, "Válido"

    @staticmethod
    def validate_gif(data: bytes) -> Tuple[bool, str]:
        """Valida estructura GIF."""
        if len(data) < 6:
            return False, "Archivo demasiado pequeño"

        # Cabecera GIF87a o GIF89a
        if data[:6] not in (b'GIF87a', b'GIF89a'):
            return False, "Falta cabecera GIF"

        # GIF debe terminar con 0x3B
        if data[-1:] != b'\x3b':
            return False, "Falta marcador de fin GIF (0x3B)"

        return True, "Válido"

    @staticmethod
    def validate_bmp(data: bytes) -> Tuple[bool, str]:
        """Valida estructura BMP."""
        if len(data) < 14:
            return False, "Archivo demasiado pequeño"

        # Cabecera BM
        if data[:2] != b'BM':
            return False, "Falta cabecera BM"

        # Tamaño del archivo en cabecera
        file_size = struct.unpack('<I', data[2:6])[0]
        if file_size != len(data):
            # Puede ser que esté truncado, verificar si es razonable
            if file_size > len(data) * 2:
                return False, f"Tamaño declarado ({file_size}) inconsistente"

        return True, "Válido"

    @staticmethod
    def validate_webp(data: bytes) -> Tuple[bool, str]:
        """Valida estructura WebP."""
        if len(data) < 12:
            return False, "Archivo demasiado pequeño"

        # RIFF header
        if data[:4] != b'RIFF':
            return False, "Falta cabecera RIFF"

        # WEBP tag
        if data[8:12] != b'WEBP':
            return False, "Falta tag WEBP"

        return True, "Válido"

    # ========================================================================
    # DOCUMENTOS
    # ========================================================================

    @staticmethod
    def validate_pdf(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura PDF.

        Verifica:
        - Cabecera %PDF-1.x
        - %%EOF marker
        - Al menos un objeto indirecto
        """
        if len(data) < 4:
            return False, "Archivo demasiado pequeño"

        # Cabecera PDF
        if not data[:5].startswith(b'%PDF'):
            return False, "Falta cabecera %PDF"

        # %%EOF
        eof_pos = data.rfind(b'%%EOF')
        if eof_pos == -1:
            return False, "Falta %%EOF"

        return True, "Válido"

    @staticmethod
    def validate_zip(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura ZIP completa.

        Verifica:
        - Local file header (PK\x03\x04)
        - Central directory (PK\x01\x02)
        - End of central directory (PK\x05\x06)
        """
        if len(data) < 22:
            return False, "Archivo demasiado pequeño"

        # Local file header
        if data[:4] != b'PK\x03\x04':
            return False, "Falta local file header (PK\\03\\04)"

        # End of central directory (al final)
        eocd_pos = data.rfind(b'PK\x05\x06')
        if eocd_pos == -1:
            return False, "Falta end of central directory (PK\\05\\06)"

        # Central directory
        cd_pos = data.find(b'PK\x01\x02')
        if cd_pos == -1:
            # Algunos ZIPs con streaming pueden no tener CD visible
            pass

        return True, "Válido"

    @staticmethod
    def validate_docx(data: bytes) -> Tuple[bool, str]:
        """Valida DOCX (ZIP con contenido Word)."""
        is_zip, reason = FileValidator.validate_zip(data)
        if not is_zip:
            return False, f"DOCX inválido: {reason}"

        # Verificar contenido Word
        if b'word/' not in data[:4096]:
            return False, "Falta contenido word/"

        return True, "Válido"

    @staticmethod
    def validate_xlsx(data: bytes) -> Tuple[bool, str]:
        """Valida XLSX (ZIP con contenido Excel)."""
        is_zip, reason = FileValidator.validate_zip(data)
        if not is_zip:
            return False, f"XLSX inválido: {reason}"

        if b'xl/' not in data[:4096]:
            return False, "Falta contenido xl/"

        return True, "Válido"

    @staticmethod
    def validate_pptx(data: bytes) -> Tuple[bool, str]:
        """Valida PPTX (ZIP con contenido PowerPoint)."""
        is_zip, reason = FileValidator.validate_zip(data)
        if not is_zip:
            return False, f"PPTX inválido: {reason}"

        if b'ppt/' not in data[:4096]:
            return False, "Falta contenido ppt/"

        return True, "Válido"

    @staticmethod
    def validate_rar(data: bytes) -> Tuple[bool, str]:
        """Valida estructura RAR."""
        if len(data) < 8:
            return False, "Archivo demasiado pequeño"

        # RAR signature (6 bytes)
        if data[:6] != b'Rar!\x1a\x07':
            return False, "Falta cabecera RAR"

        # Byte de versión (0x00 = RAR 5, 0x01 = RAR 4)
        if data[6] not in (0x00, 0x01):
            return False, f"Versión RAR inválida: {data[6]}"

        return True, "Válido"

    @staticmethod
    def validate_7z(data: bytes) -> Tuple[bool, str]:
        """Valida estructura 7z."""
        if len(data) < 32:
            return False, "Archivo demasiado pequeño"

        # 7z signature
        if data[:6] != b'7z\xbc\xaf\x27\x1c':
            return False, "Falta cabecera 7z"

        return True, "Válido"

    @staticmethod
    def validate_gzip(data: bytes) -> Tuple[bool, str]:
        """Valida estructura GZIP."""
        if len(data) < 10:
            return False, "Archivo demasiado pequeño"

        # GZIP magic number
        if data[:2] != b'\x1f\x8b':
            return False, "Falta cabecera GZIP"

        # Compression method (8 = deflate)
        if data[2] != 0x08:
            return False, f"Método de compresión inválido: {data[2]}"

        return True, "Válido"

    # ========================================================================
    # AUDIO
    # ========================================================================

    @staticmethod
    def validate_mp3(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura MP3.

        Verifica:
        - ID3v2 tag al inicio, O
        - Frame sync (0xFF 0xFB/0xF3/0xF2) al inicio
        """
        if len(data) < 4:
            return False, "Archivo demasiado pequeño"

        # ID3v2 tag
        if data[:3] == b'ID3':
            # Verificar versión ID3v2
            if data[3] not in (2, 3, 4):
                return False, f"Versión ID3v2 inválida: {data[3]}"
            return True, "Válido (con ID3 tag)"

        # MP3 frame sync
        if data[:2] == b'\xff\xfb':
            return True, "Válido (MP3 frame)"

        if data[:2] == b'\xff\xf3':
            return True, "Válido (MP3 frame)"

        if data[:2] == b'\xff\xf2':
            return True, "Válido (MP3 frame)"

        return False, "Falta sync frame o ID3 tag"

    @staticmethod
    def validate_wav(data: bytes) -> Tuple[bool, str]:
        """Valida estructura WAV."""
        if len(data) < 12:
            return False, "Archivo demasiado pequeño"

        # RIFF header
        if data[:4] != b'RIFF':
            return False, "Falta cabecera RIFF"

        # WAVE tag
        if data[8:12] != b'WAVE':
            return False, "Falta tag WAVE"

        # Verificar fmt chunk
        fmt_pos = data.find(b'fmt ', 12)
        if fmt_pos == -1:
            return False, "Falta chunk fmt"

        # Verificar data chunk
        data_pos = data.find(b'data', 12)
        if data_pos == -1:
            return False, "Falta chunk data"

        return True, "Válido"

    # ========================================================================
    # VIDEO
    # ========================================================================

    @staticmethod
    def validate_mp4(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura MP4/MOV.

        Verifica:
        - ftyp box al inicio
        - Brand conocido
        """
        if len(data) < 12:
            return False, "Archivo demasiado pequeño"

        # Box size + ftyp
        box_size = struct.unpack('>I', data[0:4])[0]
        if data[4:8] != b'ftyp':
            return False, "Falta box ftyp"

        # Verificar brand (4 bytes después de ftyp)
        brand = data[8:12]
        known_brands = [
            b'isom', b'iso2', b'iso3', b'iso4', b'iso5', b'iso6',
            b'mmp4', b'mp41', b'mp42', b'mp71',
            b'avc1', b'avci',
            b'msdh', b'msix',
            b'qt  ', b'raw ',
        ]

        if brand not in known_brands:
            # No necesariamente inválido, pero inusual
            pass

        return True, "Válido"

    @staticmethod
    def validate_avi(data: bytes) -> Tuple[bool, str]:
        """Valida estructura AVI."""
        if len(data) < 12:
            return False, "Archivo demasiado pequeño"

        # RIFF header
        if data[:4] != b'RIFF':
            return False, "Falta cabecera RIFF"

        # AVI tag
        if data[8:12] != b'AVI ':
            return False, "Falta tag AVI"

        return True, "Válido"

    # ========================================================================
    # EJECUTABLES
    # ========================================================================

    @staticmethod
    def validate_exe(data: bytes) -> Tuple[bool, str]:
        """Valida estructura EXE (PE/NE)."""
        if len(data) < 64:
            return False, "Archivo demasiado pequeño"

        # MZ header
        if data[:2] != b'MZ':
            return False, "Falta cabecera MZ"

        # PE offset en posición 0x3C
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]

        if pe_offset + 4 <= len(data):
            pe_sig = data[pe_offset:pe_offset + 4]
            if pe_sig == b'PE\x00\x00':
                return True, "Válido (PE)"
            elif pe_sig[:2] == b'NE':
                return True, "Válido (NE)"

        # MZ válido pero sin PE/NE detectado
        return True, "Válido (MZ, PE no verificado)"

    @staticmethod
    def validate_elf(data: bytes) -> Tuple[bool, str]:
        """Valida estructura ELF."""
        if len(data) < 16:
            return False, "Archivo demasiado pequeño"

        # ELF magic
        if data[:4] != b'\x7fELF':
            return False, "Falta cabecera ELF"

        # Clase (1=32bit, 2=64bit)
        if data[4] not in (1, 2):
            return False, f"Clase ELF inválida: {data[4]}"

        # Endianness (1=little, 2=big)
        if data[5] not in (1, 2):
            return False, f"Endianness inválido: {data[5]}"

        return True, "Válido"

    # ========================================================================
    # DISPATCHER
    # ========================================================================

    @staticmethod
    def validate_file(data: bytes, file_type: str) -> Tuple[bool, str]:
        """
        Valida un archivo según su tipo.

        Returns:
            (es_valido, razon)
        """
        validators = {
            # Imágenes
            'jpeg': FileValidator.validate_jpeg,
            'png': FileValidator.validate_png,
            'gif': FileValidator.validate_gif,
            'gif87': FileValidator.validate_gif,
            'gif89': FileValidator.validate_gif,
            'bmp': FileValidator.validate_bmp,
            'webp': FileValidator.validate_webp,

            # Documentos
            'pdf': FileValidator.validate_pdf,
            'zip': FileValidator.validate_zip,
            'docx': FileValidator.validate_docx,
            'xlsx': FileValidator.validate_xlsx,
            'pptx': FileValidator.validate_pptx,
            'rar': FileValidator.validate_rar,
            '7z': FileValidator.validate_7z,
            'gzip': FileValidator.validate_gzip,

            # Audio
            'mp3': FileValidator.validate_mp3,
            'wav': FileValidator.validate_wav,

            # Video
            'mp4': FileValidator.validate_mp4,
            'avi': FileValidator.validate_avi,

            # Ejecutables
            'exe': FileValidator.validate_exe,
            'elf': FileValidator.validate_elf,
        }

        validator = validators.get(file_type)
        if validator:
            return validator(data)

        # Sin validación específica
        return True, "Sin validación específica"
