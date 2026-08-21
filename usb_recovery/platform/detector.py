"""
Detección de dispositivos de almacenamiento por plataforma.

Soporta:
- Windows: Win32 API (GetDriveType, GetVolumeInformation)
- Linux: lsblk + /sys/block + /proc/partitions
- macOS: diskutil + plistlib
"""

import os
import sys
import json
import shutil
import ctypes
import ctypes.wintypes
import subprocess
from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class DeviceInfo:
    """Información de un dispositivo de almacenamiento."""

    id: str              # Identificador único (letra en Windows, /dev/sdX en Linux)
    name: str            # Nombre del volumen
    path: str            # Ruta raw para acceso directo
    filesystem: str      # Sistema de archivos (FAT32, NTFS, exFAT, ext4...)
    total_size: int      # Tamaño total en bytes
    free_size: int       # Espacio libre en bytes
    is_removable: bool   # True si es extraíble (USB, SD)
    model: str = ''      # Modelo del dispositivo (si disponible)
    serial: str = ''     # Número de serie (si disponible)

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

    @property
    def size_gb(self) -> float:
        """Tamaño en GB."""
        return self.total_size / (1024 ** 3)

    @property
    def free_gb(self) -> float:
        """Espacio libre en GB."""
        return self.free_size / (1024 ** 3)


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


# ============================================================================
# WINDOWS
# ============================================================================

class WindowsDetector(DeviceDetector):
    """Detección de dispositivos en Windows usando Win32 API."""

    DRIVE_REMOVABLE = 2

    def list_devices(self) -> List[DeviceInfo]:
        """Lista dispositivos USB conectados en Windows."""
        devices = []
        kernel32 = ctypes.windll.kernel32

        for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
            drive_path = f'{letter}:\\'

            if kernel32.GetDriveTypeW(drive_path) != self.DRIVE_REMOVABLE:
                continue

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
                ctypes.sizeof(fs_name),
            )

            if not result:
                continue

            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            kernel32.GetDiskFreeSpaceExW(
                drive_path,
                None,
                ctypes.byref(total_bytes),
                ctypes.byref(free_bytes),
            )

            devices.append(DeviceInfo(
                id=letter,
                name=volume_name.value or f'USB {letter}:',
                path=f'\\\\.\\{letter}:',
                filesystem=fs_name.value,
                total_size=total_bytes.value,
                free_size=free_bytes.value,
                is_removable=True,
                serial=f'{serial.value:08X}' if serial.value else '',
            ))

        return devices

    def get_raw_path(self, device_id: str) -> str:
        return f'\\\\.\\{device_id.upper()}:'


# ============================================================================
# LINUX
# ============================================================================

class LinuxDetector(DeviceDetector):
    """
    Detección de dispositivos en Linux.

    Usa múltiples fuentes:
    - lsblk (información principal)
    - /sys/block (verificación de removible)
    - /proc/partitions (fallback)
    """

    def list_devices(self) -> List[DeviceInfo]:
        """Lista dispositivos USB/extraíbles en Linux."""
        # Intentar con lsblk (más confiable)
        devices = self._list_with_lsblk()

        if devices:
            return devices

        # Fallback: /proc/partitions
        return self._list_with_proc()

    def _list_with_lsblk(self) -> List[DeviceInfo]:
        """Usa lsblk para listar dispositivos."""
        devices = []

        try:
            result = subprocess.run(
                ['lsblk', '-J', '-b', '-o',
                 'NAME,SIZE,FSTYPE,MOUNTPOINT,RM,MODEL,SERIAL,TRAN'],
                capture_output=True, text=True, timeout=5,
            )

            if result.returncode != 0:
                return []

            data = json.loads(result.stdout)

            for device in data.get('blockdevices', []):
                name = device.get('name', '')

                # Filtrar solo dispositivos principales (sin número de partición)
                # sd*, mmcblk*, nvme* (sin p*)
                if name.startswith('loop') or name.startswith('ram'):
                    continue

                # Verificar si es removable
                is_removable = device.get('rm', False) is True

                # También verificar por transport
                tran = device.get('tran', '') or ''
                if tran.lower() in ('usb', 'sdcard', 'mmc'):
                    is_removable = True

                # Verificar /sys/block para removible
                if not is_removable:
                    is_removable = self._check_sys_removable(name)

                if not is_removable:
                    continue

                size = int(device.get('size', 0) or 0)
                fstype = device.get('fstype', '') or ''
                model = device.get('model', '') or ''
                serial = device.get('serial', '') or ''

                # Obtener espacio libre si tiene mountpoint
                mountpoint = device.get('mountpoint', '') or ''
                free_size = 0
                if mountpoint and os.path.ismount(mountpoint):
                    try:
                        usage = shutil.disk_usage(mountpoint)
                        free_size = usage.free
                    except Exception:
                        pass

                devices.append(DeviceInfo(
                    id=name,
                    name=f'{model.strip()} ({name})' if model else name,
                    path=f'/dev/{name}',
                    filesystem=fstype,
                    total_size=size,
                    free_size=free_size,
                    is_removable=True,
                    model=model.strip(),
                    serial=serial.strip(),
                ))

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        return devices

    def _check_sys_removable(self, device_name: str) -> bool:
        """Verifica si un dispositivo es removable usando /sys/block."""
        # Limpiar nombre (quitar prefijo /dev/ si existe)
        name = device_name.replace('/dev/', '')

        sys_path = f'/sys/block/{name}/removable'
        try:
            with open(sys_path, 'r') as f:
                return f.read().strip() == '1'
        except (FileNotFoundError, PermissionError):
            return False

    def _list_with_proc(self) -> List[DeviceInfo]:
        """Fallback: usa /proc/partitions."""
        devices = []

        try:
            with open('/proc/partitions', 'r') as f:
                lines = f.readlines()[2:]

            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue

                name = parts[3]

                # Solo dispositivos principales (sin número de partición)
                if name[-1].isdigit():
                    continue

                if not name.startswith(('sd', 'mmcblk', 'nvme')):
                    continue

                # Verificar removible
                if not self._check_sys_removable(name):
                    continue

                size_kb = int(parts[2])
                total_size = size_kb * 1024

                devices.append(DeviceInfo(
                    id=name,
                    name=name,
                    path=f'/dev/{name}',
                    filesystem='',
                    total_size=total_size,
                    free_size=0,
                    is_removable=True,
                ))

        except Exception as e:
            print(f'[WARNING] Error leyendo /proc/partitions: {e}')

        return devices

    def get_raw_path(self, device_id: str) -> str:
        name = device_id.replace('/dev/', '')
        return f'/dev/{name}'


# ============================================================================
# macOS (DARWIN)
# ============================================================================

class DarwinDetector(DeviceDetector):
    """
    Detección de dispositivos en macOS.

    Usa diskutil para listar dispositivos y obtener información.
    """

    def list_devices(self) -> List[DeviceInfo]:
        """Lista dispositivos USB en macOS usando diskutil."""
        devices = []

        try:
            import plistlib

            result = subprocess.run(
                ['diskutil', 'list', '-plist', 'external', 'physical'],
                capture_output=True, timeout=5,
            )

            if result.returncode != 0:
                # Fallback: listar todos los discos
                result = subprocess.run(
                    ['diskutil', 'list', '-plist'],
                    capture_output=True, timeout=5,
                )

            if result.returncode != 0:
                return []

            plist_data = plistlib.loads(result.stdout)

            for disk in plist_data.get('AllDisks', []):
                content = plist_data.get('AllDisksAndPartitions', [])

                for disk_info in content:
                    disk_id = disk_info.get('DeviceIdentifier', '')
                    if not disk_id:
                        continue

                    # Solo discos completos (no particiones)
                    if 'media' not in disk_info.get('DeviceNode', ''):
                        continue

                    size = disk_info.get('Size', 0)
                    volume_name = disk_info.get('VolumeName', '') or disk_id

                    # Obtener información adicional con diskutil info
                    info = self._get_disk_info(disk_id)

                    devices.append(DeviceInfo(
                        id=disk_id,
                        name=f'{volume_name} ({disk_id})',
                        path=f'/dev/{disk_id}',
                        filesystem=info.get('filesystem', ''),
                        total_size=size,
                        free_size=info.get('free_size', 0),
                        is_removable=True,
                        model=info.get('model', ''),
                        serial=info.get('serial', ''),
                    ))

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            print(f'[WARNING] Error detectando dispositivos macOS: {e}')

        return devices

    def _get_disk_info(self, disk_id: str) -> dict:
        """Obtiene información detallada de un disco."""
        info = {}

        try:
            result = subprocess.run(
                ['diskutil', 'info', '-plist', disk_id],
                capture_output=True, timeout=5,
            )

            if result.returncode == 0:
                import plistlib
                plist = plistlib.loads(result.stdout)

                info['filesystem'] = plist.get('FilesystemType', '')
                info['model'] = plist.get('MediaName', '') or plist.get('Product', '')
                info['serial'] = plist.get('SerialNumber', '')

                # Espacio libre (solo si tiene volumen montado)
                free = plist.get('FreeSpace', 0)
                if free:
                    info['free_size'] = free

        except Exception:
            pass

        return info

    def get_raw_path(self, device_id: str) -> str:
        return f'/dev/{device_id}'


# ============================================================================
# FACTORY
# ============================================================================

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


def list_all_devices() -> List[DeviceInfo]:
    """Función de conveniencia: lista dispositivos en cualquier plataforma."""
    return get_detector().list_devices()
