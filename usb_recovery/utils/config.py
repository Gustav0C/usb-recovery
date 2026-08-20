"""
Configuración centralizada para USB Recovery Tool.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuración para un escaneo."""
    
    # Dispositivo
    device_path: str = ''
    
    # Salida
    output_dir: str = './recovered'
    
    # Filtros
    types_filter: List[str] = field(default_factory=list)
    
    # Rango de escaneo
    offset_start: int = 0
    max_size: Optional[int] = None
    
    # Rendimiento
    chunk_size: int = 1024 * 1024  # 1MB
    parallel_workers: int = 4
    
    # Funcionalidad
    validate_integrity: bool = True
    deduplicate: bool = True
    save_log: bool = True
    
    def validate(self) -> bool:
        """Valida que la configuración sea válida."""
        if not self.device_path:
            raise ValueError("device_path es requerido")
        
        if self.chunk_size < 1024:
            raise ValueError("chunk_size debe ser al menos 1024 bytes")
        
        return True
    
    def to_dict(self) -> dict:
        """Convierte a diccionario para serialización."""
        return {
            'device_path': self.device_path,
            'output_dir': self.output_dir,
            'types_filter': self.types_filter,
            'offset_start': self.offset_start,
            'max_size': self.max_size,
            'chunk_size': self.chunk_size,
            'parallel_workers': self.parallel_workers,
            'validate_integrity': self.validate_integrity,
            'deduplicate': self.deduplicate,
            'save_log': self.save_log,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScanConfig':
        """Crea desde un diccionario."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
