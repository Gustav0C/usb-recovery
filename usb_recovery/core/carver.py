"""
Motor principal de file carving para recuperación de archivos.
"""

import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List

from .signatures import FILE_SIGNATURES
from .validator import FileValidator
from .deduplicator import FileDeduplicator, fast_hash
from ..utils.logging import ScanLogger


class FileCarver:
    """Motor principal de recuperación de archivos mediante file carving."""
    
    # Overlap para capturar firmas que cruzan chunks (8KB)
    OVERLAP_SIZE = 8192
    
    def __init__(self, device_path: str, output_dir: str, chunk_size: int = 1024 * 1024):
        """
        Args:
            device_path: Ruta al dispositivo (ej: \\\\.\\E:)
            output_dir: Directorio de salida para archivos recuperados
            chunk_size: Tamaño de bloque de lectura (default: 1MB)
        """
        self.device_path = device_path
        self.output_dir = Path(output_dir)
        self.chunk_size = chunk_size
        self.recovered_files: List[Dict] = []
        self.deduplicator = FileDeduplicator()
        self.logger = ScanLogger(output_dir)
        self.stats = {
            'bytes_scanned': 0,
            'files_found': 0,
            'files_skipped_duplicates': 0,
            'errors': 0,
            'skipped': 0,
        }
    
    def _match_header(self, data: bytes, sig: Dict, offset: int) -> bool:
        """Verifica si los bytes en offset coinciden con la firma."""
        header = sig.get('header')
        if not header:
            return False
        
        if data[offset:offset + len(header)] != header:
            return False
        
        # Verificación adicional para firmas compuestas
        if 'check_offset' in sig and 'check_bytes' in sig:
            check_pos = offset + sig['check_offset']
            check_data = data[check_pos:check_pos + len(sig['check_bytes'])]
            if check_data != sig['check_bytes']:
                return False
        
        return True
    
    def _match_footer(self, data: bytes, sig: Dict, offset: int) -> Optional[int]:
        """Busca el footer del archivo y retorna el tamaño total."""
        footer = sig.get('footer')
        if not footer:
            # Sin footer: usar tamaño máximo o buscar siguiente cabecera
            return min(sig.get('max_size', 10 * 1024 * 1024), self.chunk_size * 2)
        
        # Buscar footer en los datos disponibles
        search_end = min(offset + sig.get('max_size', 10 * 1024 * 1024), len(data))
        footer_pos = data.find(footer, offset + 4, search_end)
        
        if footer_pos != -1:
            return footer_pos + len(footer) - offset
        
        return None
    
    def _check_content_type(self, data: bytes, sig: Dict, offset: int) -> bool:
        """Verifica el contenido interno para archivos ZIP-based (DOCX, XLSX, PPTX)."""
        if 'check_content' not in sig:
            return True
        
        # Para archivos ZIP, necesitamos leer más datos
        check_range = min(offset + 1024, len(data))
        chunk = data[offset:check_range]
        
        return sig['check_content'] in chunk
    
    def _carve_file(self, data: bytes, offset: int, sig: Dict) -> Optional[bytes]:
        """Extrae un archivo desde los datos."""
        ext = sig['ext']
        
        # Calcular tamaño del archivo
        file_size = self._match_footer(data, sig, offset)
        if file_size is None:
            return None
        
        # No exceder tamaño máximo
        max_size = sig.get('max_size', 10 * 1024 * 1024)
        file_size = min(file_size, max_size)
        
        # Extraer datos
        file_data = data[offset:offset + file_size]
        
        # Verificar que no esté vacío o corrupto
        if len(file_data) < 8:
            return None
        
        # Para archivos binarios, verificar que tenga datos no-cero
        if ext in ('.exe', '.dll', '.elf'):
            non_zero = sum(1 for b in file_data[:1024] if b != 0)
            if non_zero < 100:
                return None
        
        return file_data
    
    def _generate_filename(self, file_type: str, index: int) -> str:
        """Genera nombre de archivo único."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ext = FILE_SIGNATURES[file_type]['ext']
        return f'recovered_{timestamp}_{index:04d}{ext}'
    
    def _write_file(self, data: bytes, filename: str) -> Optional[Path]:
        """Escribe los datos recuperados a un archivo."""
        output_path = self.output_dir / filename
        try:
            output_path.write_bytes(data)
            return output_path
        except Exception as e:
            print(f'  [ERROR] No se pudo escribir {filename}: {e}')
            self.stats['errors'] += 1
            return None
    
    def scan_device(self, types_filter: Optional[List[str]] = None, 
                    offset_start: int = 0, max_size: Optional[int] = None) -> List[Dict]:
        """
        Escanea el dispositivo buscando archivos.
        
        Args:
            types_filter: Lista de tipos de archivo a buscar (None = todos)
            offset_start: Offset inicial de lectura
            max_size: Tamaño máximo a escanear (None = todo el dispositivo)
        
        Returns:
            Lista de archivos recuperados
        """
        print(f'\n{"="*60}')
        print(f'  USB File Recovery Tool')
        print(f'{"="*60}')
        print(f'  Dispositivo: {self.device_path}')
        print(f'  Salida: {self.output_dir}')
        print(f'  Tipos: {", ".join(types_filter) if types_filter else "Todos"}')
        print(f'{"="*60}\n')
        
        # Crear directorio de salida
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Log de inicio de escaneo
        self.logger.log_scan_start(self.device_path, {
            'output_dir': str(self.output_dir),
            'types_filter': types_filter,
            'offset_start': offset_start,
            'max_size': max_size,
        })
        
        # Filtrar firmas
        signatures = FILE_SIGNATURES
        if types_filter:
            signatures = {k: v for k, v in FILE_SIGNATURES.items() 
                         if k in types_filter or v['ext'].lstrip('.') in types_filter}
        
        if not signatures:
            print('[ERROR] No se encontraron firmas para los tipos solicitados')
            return []
        
        print(f'[*] Buscando {len(signatures)} tipos de archivo...\n')
        
        # Abrir dispositivo
        try:
            # Intentar acceso raw al dispositivo
            device = open(self.device_path, 'rb')
        except PermissionError:
            print('[ERROR] Se requieren permisos de administrador para leer el dispositivo.')
            print('        Ejecute el script como administrador.')
            return []
        except FileNotFoundError:
            print(f'[ERROR] Dispositivo no encontrado: {self.device_path}')
            print('        Verifique la letra de unidad.')
            return []
        except Exception as e:
            print(f'[ERROR] No se pudo abrir el dispositivo: {e}')
            return []
        
        try:
            file_index = 0
            offset = offset_start
            buffer = b''
            
            # Tamaño total a escanear
            if max_size:
                end_offset = offset_start + max_size
            else:
                device.seek(0, 2)  # Fin del archivo
                end_offset = device.tell()
                device.seek(offset_start)
            
            total_size = end_offset - offset_start
            progress_interval = max(1, total_size // 100)
            
            print(f'[*] Escaneando {total_size / (1024*1024):.1f} MB...\n')
            
            while offset < end_offset:
                # Leer chunk
                read_size = min(self.chunk_size, end_offset - offset)
                chunk = device.read(read_size)
                
                if not chunk:
                    break
                
                # Concatenar con buffer anterior (para firmas que cruzan chunks)
                search_data = buffer + chunk
                
                # Buscar firmas en este chunk
                for sig_name, sig in signatures.items():
                    # Determinar rango de búsqueda
                    start_pos = len(buffer) if buffer else 0
                    
                    pos = start_pos
                    while pos < len(search_data) - 4:
                        # Verificar cabecera
                        if self._match_header(search_data, sig, pos):
                            # Verificar contenido (para DOCX/XLSX/PPTX)
                            if not self._check_content_type(search_data, sig, pos):
                                pos += 1
                                continue
                            
                            # Intentar extraer archivo
                            file_data = self._carve_file(search_data, pos, sig)
                            
                            if file_data and len(file_data) > 100:
                                # Verificar si es duplicado
                                if self.deduplicator.is_duplicate(None, file_data):
                                    self.stats['files_skipped_duplicates'] += 1
                                    pos += len(file_data) if file_data else 1
                                    continue
                                
                                # Validar integridad del archivo
                                is_valid, reason = FileValidator.validate_file(file_data, sig_name)
                                if not is_valid:
                                    self.stats['skipped'] += 1
                                    self.logger.log_event('file_skipped', {
                                        'reason': reason,
                                        'type': sig_name,
                                        'size': len(file_data),
                                        'offset': offset + pos - len(buffer),
                                    })
                                    pos += len(file_data) if file_data else 1
                                    continue
                                
                                # Archivo válido y único
                                filename = self._generate_filename(sig_name, file_index)
                                output_path = self._write_file(file_data, filename)
                                
                                if output_path:
                                    # Actualizar hash con la ruta del archivo
                                    self.deduplicator.hash_map[fast_hash(file_data)] = str(output_path)
                                    
                                    file_info = {
                                        'offset': offset + pos - len(buffer),
                                        'size': len(file_data),
                                        'type': sig_name,
                                        'ext': sig['ext'],
                                        'path': str(output_path),
                                        'hash': fast_hash(file_data),
                                    }
                                    self.recovered_files.append(file_info)
                                    self.stats['files_found'] += 1
                                    file_index += 1
                                    
                                    # Log del archivo encontrado
                                    self.logger.log_file_found(file_info)
                                    
                                    print(f'  [+] {filename} ({len(file_data)/1024:.1f} KB) '
                                          f'en offset 0x{offset + pos - len(buffer):08X}')
                                else:
                                    # Error al escribir
                                    self.stats['errors'] += 1
                            
                            # Avanzar más allá de este archivo encontrado
                            if file_data:
                                pos += len(file_data)
                            else:
                                pos += 1
                        else:
                            pos += 1
                
                # Actualizar buffer (mantener últimos bytes por si una firma cruza chunks)
                # Usar OVERLAP_SIZE para no perder firmas grandes
                buffer = chunk[-self.OVERLAP_SIZE:] if len(chunk) > self.OVERLAP_SIZE else chunk
                
                # Progreso
                self.stats['bytes_scanned'] += read_size
                offset += read_size
                
                if offset % progress_interval < self.chunk_size:
                    progress = (offset - offset_start) / total_size * 100
                    print(f'\r[*] Progreso: {progress:.1f}% '
                          f'({self.stats["files_found"]} archivos encontrados)', 
                          end='', flush=True)
        
        finally:
            device.close()
        
        # Log de finalización
        self.logger.log_scan_complete(self.stats)
        self.logger.save()
        
        print(f'\n\n{"="*60}')
        print(f'  ESCANEO COMPLETADO')
        print(f'{"="*60}')
        print(f'  Bytes escaneados: {self.stats["bytes_scanned"] / (1024*1024):.1f} MB')
        print(f'  Archivos encontrados: {self.stats["files_found"]}')
        print(f'  Duplicados omitidos: {self.stats["files_skipped_duplicates"]}')
        print(f'  Archivos inválidos omitidos: {self.stats["skipped"]}')
        print(f'  Errores: {self.stats["errors"]}')
        print(f'  Resultados guardados en: {self.output_dir}')
        print(f'  Log guardado en: {self.logger.log_file}')
        print(f'{"="*60}\n')
        
        return self.recovered_files
