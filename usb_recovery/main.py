#!/usr/bin/env python3
"""
USB Recovery Tool - Punto de entrada unificado
"""

import sys
import argparse
from pathlib import Path

from .core.carver import FileCarver
from .core.signatures import FILE_SIGNATURES
from .platform.detector import get_detector, DeviceDetector
from .utils.config import ScanConfig


def list_devices():
    """Lista dispositivos USB conectados."""
    detector = get_detector()
    devices = detector.list_devices()
    
    if not devices:
        print('\n[*] No se encontraron dispositivos USB.')
        print('    Asegúrese de que el USB esté conectado.')
        return
    
    print('\n[*] Dispositivos USB conectados:\n')
    
    for dev in devices:
        total_gb = dev.total_size / (1024**3)
        free_gb = dev.free_size / (1024**3)
        used_gb = total_gb - free_gb
        
        print(f"    {dev.id}: - {dev.name}")
        print(f"      Filesystem: {dev.filesystem or 'Desconocido'}")
        print(f"      Tamaño: {total_gb:.1f} GB (Usado: {used_gb:.1f} GB, "
              f"Libre: {free_gb:.1f} GB)")
        print(f"      Para usar: python -m usb_recovery --device {dev.path} "
              f"--output ./recovered")
        print()


def run_scan(config: ScanConfig):
    """Ejecuta un escaneo con la configuración dada."""
    carver = FileCarver(
        device_path=config.device_path,
        output_dir=config.output_dir,
        chunk_size=config.chunk_size
    )
    
    try:
        results = carver.scan_device(
            types_filter=config.types_filter if config.types_filter else None,
            offset_start=config.offset_start,
            max_size=config.max_size
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
            print(f'    Verifique los archivos manualmente en: {config.output_dir}')
    
    except KeyboardInterrupt:
        print('\n\n[!] Escaneo interrumpido por el usuario.')
        print(f'    Archivos recuperados hasta el momento: {len(carver.recovered_files)}')
        sys.exit(1)
    except Exception as e:
        print(f'\n[ERROR] Error inesperado: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Punto de entrada principal."""
    parser = argparse.ArgumentParser(
        description='USB File Recovery Tool - Recupera archivos eliminados de USB',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python -m usb_recovery --list-devices
  python -m usb_recovery --device \\\\.\\E: --output ./recuperados
  python -m usb_recovery --device \\\\.\\E: --output ./recuperados --types jpeg,pdf
  python -m usb_recovery --device \\\\.\\E: --output ./recuperados --size 1GB
        """
    )
    
    parser.add_argument('--device', '-d',
                       help='Ruta del dispositivo (ej: \\\\.\\E: o /dev/sdb)')
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
        list_devices()
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
    types_filter = []
    if args.types:
        types_filter = [t.strip().lower() for t in args.types.split(',')]
    
    # Crear configuración
    config = ScanConfig(
        device_path=args.device,
        output_dir=args.output,
        types_filter=types_filter,
        offset_start=args.offset,
        max_size=max_size,
        chunk_size=args.chunk_size,
    )
    
    # Ejecutar escaneo
    run_scan(config)


if __name__ == '__main__':
    main()
