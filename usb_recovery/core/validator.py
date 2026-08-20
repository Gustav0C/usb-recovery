"""
Validación de integridad de archivos recuperados.
"""

from typing import Tuple


class FileValidator:
    """Valida integridad de archivos recuperados."""
    
    @staticmethod
    def validate_jpeg(data: bytes) -> Tuple[bool, str]:
        """
        Valida estructura JPEG básica.
        
        Returns:
            (es_valido, razon)
        """
        if len(data) < 4:
            return False, "Archivo demasiado pequeño"
        
        # Verificar SOI marker (Start of Image)
        if data[:2] != b'\xff\xd8':
            return False, "Falta marker SOI (FFD8)"
        
        # Verificar que termine con EOI marker (End of Image)
        # Buscar en los últimos 2 bytes
        if data[-2:] != b'\xff\xd9':
            # Algunos JPEGs pueden tener datos basura al final
            # Buscar EOI en los últimos 16 bytes
            eoi_found = False
            for i in range(max(0, len(data) - 16), len(data) - 1):
                if data[i:i+2] == b'\xff\xd9':
                    eoi_found = True
                    break
            
            if not eoi_found:
                return False, "Falta marker EOI (FFD9)"
        
        # Verificar markers APP0 o APP1 (JFIF o EXI)
        if data[2:4] not in (b'\xff\xe0', b'\xff\xe1'):
            # No es un error fatal, pero es inusual
            pass
        
        return True, "Válido"
    
    @staticmethod
    def validate_png(data: bytes) -> Tuple[bool, str]:
        """Valida estructura PNG básica."""
        if len(data) < 8:
            return False, "Archivo demasiado pequeño"
        
        # Verificar cabecera PNG
        if data[:8] != b'\x89PNG\r\n\x1a\n':
            return False, "Falta cabecera PNG"
        
        # Verificar IEND chunk
        iend_pos = data.find(b'IEND')
        if iend_pos == -1:
            return False, "Falta chunk IEND"
        
        return True, "Válido"
    
    @staticmethod
    def validate_pdf(data: bytes) -> Tuple[bool, str]:
        """Valida estructura PDF básica."""
        if len(data) < 4:
            return False, "Archivo demasiado pequeño"
        
        # Verificar cabecera PDF
        if not data[:4].startswith(b'%PDF'):
            return False, "Falta cabecera %PDF"
        
        # Verificar %%EOF
        eof_pos = data.rfind(b'%%EOF')
        if eof_pos == -1:
            return False, "Falta marcador %%EOF"
        
        return True, "Válido"
    
    @staticmethod
    def validate_file(data: bytes, file_type: str) -> Tuple[bool, str]:
        """Valida un archivo según su tipo."""
        validators = {
            'jpeg': FileValidator.validate_jpeg,
            'png': FileValidator.validate_png,
            'pdf': FileValidator.validate_pdf,
        }
        
        validator = validators.get(file_type)
        if validator:
            return validator(data)
        
        # Sin validación específica: asumir válido
        return True, "Sin validación"
