"""
Detección de dispositivos de almacenamiento por plataforma.
"""

import sys
import ctypes
import ctypes.wintypes
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class DeviceInfo:
    """Información de un dispositivo de almacenamiento."""
    
    id: str  # Identificador único (letra en Windows, path en Linux)
    name: str  # Nombre del volumen
    path: str  # Ruta raw para acceso directo
    filesystem: str  # Sistema de archivos
    total_size: int  # Tamaño total en bytes
    free_size: int  # Espacio libre en bytes
    is_removable: bool  # True si es extraíble (USB)
    
    @property
    def used_size(self) -> int:
        """Espacio usado en bytes."""
        return self.total_size - self.free_size
    
    @property
    def used_percent(self) -> float:
        """Porcentaje de uso."""
        if self.total_size == 0:
            return 0.0
        return (self.used_size / self.total_size) * 100


class DeviceDetector(ABC):
    """Interfaz abstracta para detección de dispositivos."""
    
    @abstractmethod
    def list_devices(self) -> List[DeviceInfo]:
        """Lista todos los dispositivos de almacenamiento extraíbles."""
        pass
    
    @abstractmethod
    def get_raw_path(self, device_id: str) -> str:
        """Obtiene la ruta raw del dispositivo para acceso directo."""
        pass


class WindowsDetector(DeviceDetector):
    """Detección de dispositivos en Windows."""
    
    def list_devices(self) -> List[DeviceInfo]:
        """Lista dispositivos USB conectados en Windows."""
        devices = []
        
        kernel32 = ctypes.windll.kernel32
        
        for drive_letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
            drive_path = f'{drive_letter}:\\'
            
            drive_type = kernel32.GetDriveTypeW(drive_path)
            # DRIVE_REMOVABLE = 2
            if drive_type == 2:
                # Obtener información del volumen
                volume_name = ctypes.create_unicode_buffer(256)
                serial = ctypes.wintypes.DWORD()
                max_comp = ctypes.wintypes.DWORD()
                fs_flags = ctypes.wintypes.DWORD()
                fs_name = ctypes.create_unicode_buffer(256)
                
                result = kernel32.GetVolumeInformationW(
                    drive_path,
                    volume_name,
                    ctypes.sizeof(volume_name),
                    ctypes.byref(serial),
                    ctypes.byref(max_comp),
                    ctypes.byref(fs_flags),
                    fs_name,
                    ctypes.sizeof(fs_name)
                )
                
                if result:
                    free_bytes = ctypes.c_ulonglong(0)
                    total_bytes = ctypes.c_ulonglong(0)
                    kernel32.GetDiskFreeSpaceExW(
                        drive_path,
                        None,
                        ctypes.byref(total_bytes),
                        ctypes.byref(free_bytes)
                    )
                    
                    devices.append(DeviceInfo(
                        id=drive_letter,
                        name=volume_name.value or f'USB {drive_letter}:',
                        path=f'\\\\.\\{drive_letter}:',
                        filesystem=fs_name.value,
                        total_size=total_bytes.value,
                        free_size=free_bytes.value,
                        is_removable=True,
                    ))
        
        return devices
    
    def get_raw_path(self, device_id: str) -> str:
        """Obtiene la ruta raw del dispositivo para lectura directa."""
        return f'\\\\.\\{device_id.upper()}:'


class LinuxDetector(DeviceDetector):
    """Detección de dispositivos en Linux."""
    
    def list_devices(self) -> List[DeviceInfo]:
        """Lista dispositivos USB en Linux usando /proc/partitions."""
        devices = []
        
        try:
            # Leer /proc/partitions
            with open('/proc/partitions', 'r') as f:
                lines = f.readlines()[2:]  # Saltar cabecera
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    device_name = parts[3]
                    # Filtrar dispositivos principales (sin número de partición)
                    if not any(c.isdigit() for c in device_name[-1:]):
                        # Verificar si es USB (sd* o mmcblk*)
                        if device_name.startswith(('sd', 'mmcblk')):
                            device_path = f'/dev/{device_name}'
                            # Obtener tamaño
                            size_kb = int(parts[2])
                            total_size = size_kb * 1024
                            
                            devices.append(DeviceInfo(
                                id=device_name,
                                name=f'USB {device_name}',
                                path=device_path,
                                filesystem='',  # Se detectará después
                                total_size=total_size,
                                free_size=0,  # Se obtendrá después
                                is_removable=True,
                            ))
        except Exception as e:
            print(f'[WARNING] Error leyendo /proc/partitions: {e}')
        
        return devices
    
    def get_raw_path(self, device_id: str) -> str:
        """Obtiene la ruta raw del dispositivo."""
        return f'/dev/{device_id}'


class DarwinDetector(DeviceDetector):
    """Detección de dispositivos en macOS."""
    
    def list_devices(self) -> List[DeviceInfo]:
        """Lista dispositivos USB en macOS usando diskutil."""
        devices = []
        
        try:
            import subprocess
            result = subprocess.run(
                ['diskutil', 'list', '-plist'],
                capture_output=True,
                text=True
            )
            
            # Parsear plist simplificado
            # En una implementación real, usaríamos plistlib
            # Por ahora, retornamos lista vacía
            pass
        
        except Exception as e:
            print(f'[WARNING] Error detectando dispositivos macOS: {e}')
        
        return devices
    
    def get_raw_path(self, device_id: str) -> str:
        """Obtiene la ruta raw del dispositivo."""
        return f'/dev/{device_id}'


def get_detector() -> DeviceDetector:
    """Obtiene el detector apropiado para la plataforma actual."""
    if sys.platform == 'win32':
        return WindowsDetector()
    elif sys.platform == 'darwin':
        return DarwinDetector()
    elif sys.platform.startswith('linux'):
        return LinuxDetector()
    else:
        raise RuntimeError(f'Plataforma no soportada: {sys.platform}')
