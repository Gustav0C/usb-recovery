#!/usr/bin/env python3
"""
USB File Recovery Tool
======================
Recupera archivos eliminados de dispositivos USB mediante técnicas de file carving.

Uso:
    python usb_recovery.py --device \\\\.\\E: --output ./recovered
    python usb_recovery.py --device \\\\.\\E: --output ./recovered --types jpeg,pdf
    python usb_recovery.py --list-devices

AVISO: Use solo en dispositivos donde tenga autorización para recuperar datos.

Este archivo es para compatibilidad. Para la versión modular, use:
    python -m usb_recovery
"""

# Importar desde la nueva estructura modular
from usb_recovery.core.signatures import FILE_SIGNATURES
from usb_recovery.core.carver import FileCarver
from usb_recovery.core.validator import FileValidator
from usb_recovery.core.deduplicator import FileDeduplicator, fast_hash
from usb_recovery.platform.detector import get_detector, DeviceDetector, DeviceInfo
from usb_recovery.utils.logging import ScanLogger
from usb_recovery.utils.config import ScanConfig

# Para compatibilidad con código existente
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Optional


def list_usb_devices() -> List[DeviceInfo]:
    """
    Lista dispositivos USB conectados en cualquier plataforma.
    """
    detector = get_detector()
    return detector.list_devices()


def get_device_path_windows(device_letter: str) -> str:
    """Obtiene la ruta raw del dispositivo para lectura directa."""
    detector = get_detector()
    return detector.get_raw_path(device_letter)


# ============================================================================
# INTERFAZ CLI (para compatibilidad)
# ============================================================================

def main():
    """Función principal para compatibilidad."""
    parser = argparse.ArgumentParser(
        description='USB File Recovery Tool - Recupera archivos eliminados de USB',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python usb_recovery.py --list-devices
  python usb_recovery.py --device \\\\.\\E: --output ./recuperados
  python usb_recovery.py --device \\\\.\\E: --output ./recuperados --types jpeg,pdf
  python usb_recovery.py --device \\\\.\\E: --output ./recuperados --offset 0 --size 1GB
        """
    )
    
    parser.add_argument('--device', '-d',
                       help='Ruta del dispositivo (ej: \\\\.\\E:)')
    parser.add_argument('--output', '-o', default='./recovered',
                       help='Directorio de salida (default: ./recovered)')
    parser.add_argument('--list-devices', '-l', action='store_true',
                       help='Listar dispositivos USB conectados')
    parser.add_argument('--types', '-t',
                       help='Tipos de archivo a buscar (separados por coma)')
    parser.add_argument('--offset', type=lambda x: int(x, 0), default=0,
                       help='Offset inicial de escaneo (default: 0)')
    parser.add_argument('--size', '-s',
                       help='Tamaño máximo a escaneo (ej: 1GB, 500MB)')
    parser.add_argument('--chunk-size', type=int, default=1024*1024,
                       help='Tamaño de bloque de lectura en bytes (default: 1MB)')
    
    args = parser.parse_args()
    
    # Listar dispositivos
    if args.list_devices:
        print('\n[*] Dispositivos USB conectados:\n')
        devices = list_usb_devices()
        
        if not devices:
            print('    No se encontraron dispositivos USB.')
            print('    Asegúrese de que el USB esté conectado.')
        else:
            for dev in devices:
                print(f"    {dev.id} - {dev.name}")
                print(f"      Ruta: {dev.path}")
                print(f"      Filesystem: {dev.filesystem or 'desconocido'}")
                print(f"      Tamaño: {dev.size_gb:.1f} GB "
                      f"(Usado: {dev.used_size/(1024**3):.1f} GB, "
                      f"Libre: {dev.free_gb:.1f} GB)")
                if dev.model:
                    print(f"      Modelo: {dev.model}")
                if dev.serial:
                    print(f"      Serie: {dev.serial}")
                print(f"      Para usar: python usb_recovery.py --device {dev.path} "
                      f"--output ./recovered")
                print()
        
        sys.exit(0)
    
    # Validar argumentos
    if not args.device:
        parser.error('Se requiere --device o --list-devices')
    
    # Parsear tamaño
    max_size = None
    if args.size:
        size_str = args.size.upper()
        if size_str.endswith('GB'):
            max_size = int(float(size_str[:-2]) * 1024**3)
        elif size_str.endswith('MB'):
            max_size = int(float(size_str[:-2]) * 1024**2)
        elif size_str.endswith('KB'):
            max_size = int(float(size_str[:-2]) * 1024)
        else:
            max_size = int(size_str)
    
    # Parsear tipos
    types_filter = None
    if args.types:
        types_filter = [t.strip().lower() for t in args.types.split(',')]
    
    # Crear carver y escanear
    carver = FileCarver(
        device_path=args.device,
        output_dir=args.output,
        chunk_size=args.chunk_size
    )
    
    try:
        results = carver.scan_device(
            types_filter=types_filter,
            offset_start=args.offset,
            max_size=max_size
        )
        
        if results:
            print('\n[*] Resumen de archivos recuperados:\n')
            by_type = {}
            for f in results:
                t = f['type']
                by_type[t] = by_type.get(t, 0) + 1
            
            for file_type, count in sorted(by_type.items()):
                ext = FILE_SIGNATURES[file_type]['ext']
                print(f'    {ext}: {count} archivos')
            
            print(f'\n    Total: {len(results)} archivos')
            print(f'\n    NOTA: Algunos archivos pueden estar corruptos.')
            print(f'    Verifique los archivos manualmente en: {args.output}')
    
    except KeyboardInterrupt:
        print('\n\n[!] Escaneo interrumpido por el usuario.')
        print(f'    Archivos recuperados hasta el momento: {len(carver.recovered_files)}')
        sys.exit(1)
    except Exception as e:
        print(f'\n[ERROR] Error inesperado: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
