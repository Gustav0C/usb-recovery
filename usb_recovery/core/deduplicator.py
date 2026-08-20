"""
Deduplicación de archivos mediante hash rápido.
"""

import hashlib
from typing import Dict


def fast_hash(data: bytes, sample_size: int = 8192) -> str:
    """
    Hash rápido para deduplicación.
    Usa una muestra del archivo para velocidad (no calcula hash completo).
    
    Args:
        data: Datos del archivo
        sample_size: Tamaño de muestra para hash (default 8KB)
    
    Returns:
        Hash hexadecimal de la muestra
    """
    if len(data) <= sample_size:
        # Archivo pequeño: hash completo
        return hashlib.md5(data).hexdigest()
    
    # Archivo grande: hash de inicio + medio + final
    start = data[:sample_size // 2]
    middle = data[len(data) // 2 : len(data) // 2 + sample_size // 4]
    end = data[-sample_size // 4:]
    
    hasher = hashlib.md5()
    hasher.update(start)
    hasher.update(middle)
    hasher.update(end)
    
    return hasher.hexdigest()


class FileDeduplicator:
    """Elimina archivos duplicados basándose en hash."""
    
    def __init__(self):
        self.hash_map: Dict[str, str] = {}  # hash -> file_path
        self.duplicates_found: int = 0
    
    def is_duplicate(self, file_path: str, data: bytes) -> bool:
        """
        Verifica si un archivo es duplicado.
        
        Returns:
            True si es duplicado (no guardarlo)
        """
        file_hash = fast_hash(data)
        
        if file_hash in self.hash_map:
            self.duplicates_found += 1
            return True
        
        self.hash_map[file_hash] = file_path
        return False
