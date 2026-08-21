"""
Módulo de rendimiento para USB Recovery Tool.

Optimizaciones:
1. Búsqueda multi-patrón con pre-filtrado por byte frecuente
2. I/O nativo Windows (CreateFile con NO_BUFFERING)
3. Escaneo paralelo con ProcessPoolExecutor
4. Caché de offsets para reescaneos rápidos
"""

import os
import sys
import json
import ctypes
import ctypes.wintypes
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, as_completed

from .signatures import FILE_SIGNATURES


# ============================================================================
# 1. BUSQUEDA MULTI-PATRON OPTIMIZADA
# ============================================================================

@dataclass
class SignatureIndex:
    """Indice optimizado para busqueda rapida de firmas."""
    first_byte_map: Dict[int, List[Tuple[str, bytes]]] = field(default_factory=dict)
    first_bytes: Set[int] = field(default_factory=set)


class MultiPatternSearcher:
    """
    Busqueda multi-patron optimizada sin dependencias externas.

    Estrategia:
    1. Indexar firmas por primer byte (pre-filtrado instantaneo)
    2. Para cada posicion, verificar solo si el primer byte coincide
    3. Verificar cabecera completa solo en candidatos
    4. Verificacion secundaria (check_bytes, check_content) solo si pasa
    """

    def __init__(self, signatures: Dict[str, Dict]):
        self.index = self._build_index(signatures)
        self.signatures = signatures

    def _build_index(self, signatures: Dict[str, Dict]) -> SignatureIndex:
        """Construye indice por primer byte."""
        index = SignatureIndex()

        for sig_name, sig in signatures.items():
            header = sig.get('header', b'')
            if not header:
                continue

            first_byte = header[0]
            index.first_bytes.add(first_byte)

            if first_byte not in index.first_byte_map:
                index.first_byte_map[first_byte] = []
            index.first_byte_map[first_byte].append((sig_name, header))

            # Indexar header2 si existe
            if 'header2' in sig:
                h2 = sig['header2']
                fb2 = h2[0]
                index.first_bytes.add(fb2)
                if fb2 not in index.first_byte_map:
                    index.first_byte_map[fb2] = []
                index.first_byte_map[fb2].append((sig_name, h2))

        return index

    def search(self, data: bytes, base_offset: int = 0) -> List[Tuple[str, int]]:
        """
        Busca todas las firmas en los datos.

        Returns:
            Lista de (sig_name, offset_abs)
        """
        matches = []
        data_len = len(data)
        first_bytes = self.index.first_bytes
        first_byte_map = self.index.first_byte_map

        for i in range(data_len):
            byte = data[i]

            if byte not in first_bytes:
                continue

            for sig_name, header in first_byte_map[byte]:
                header_len = len(header)

                if i + header_len > data_len:
                    continue

                if data[i:i + header_len] != header:
                    continue

                sig = self.signatures[sig_name]
                if self._verify_secondary(data, sig, i):
                    matches.append((sig_name, base_offset + i))

        return matches

    def _verify_secondary(self, data: bytes, sig: Dict, offset: int) -> bool:
        """Verificaciones secundarias (check_bytes, check_content)."""
        if 'check_offset' in sig and 'check_bytes' in sig:
            check_pos = offset + sig['check_offset']
            check_end = check_pos + len(sig['check_bytes'])
            if check_end > len(data):
                return False
            if data[check_pos:check_end] != sig['check_bytes']:
                return False

        if 'check_content' in sig:
            check_range = min(offset + 4096, len(data))
            if sig['check_content'] not in data[offset:check_range]:
                return False

        return True


# ============================================================================
# 2. I/O NATIVO WINDOWS
# ============================================================================

# Constantes de Windows API
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_BEGIN = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class NativeDeviceReader:
    """
    Lector de dispositivos nativo para Windows.

    Usa CreateFileW con FILE_FLAG_NO_BUFFERING para leer directamente
    del dispositivo sin pasar por la cache del sistema operativo.

    Ventajas:
    - Sin overhead de cache del SO
    - Lectura secuencial optimizada
    - Acceso raw al dispositivo

    Restricciones:
    - Solo Windows
    - Lecturas deben ser alineadas a 512 bytes (sectores)
    - Requiere permisos de administrador
    """

    def __init__(self, device_path: str):
        self.device_path = device_path
        self.handle = None
        self._open()

    def _open(self):
        """Abre el dispositivo con acceso raw."""
        if sys.platform != 'win32':
            raise RuntimeError("NativeDeviceReader solo esta disponible en Windows")

        kernel32 = ctypes.windll.kernel32

        self.handle = kernel32.CreateFileW(
            self.device_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )

        if self.handle == INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            raise RuntimeError(
                f"No se pudo abrir dispositivo: {self.device_path} "
                f"(error {error}). Se ejecuta como administrador?"
            )

    def read_aligned(self, size: int, offset: int = 0) -> bytes:
        """
        Lee datos del dispositivo con alineacion a sector (512 bytes).

        Args:
            size: Tamano a leer ( sera redondeado hacia arriba a multiplo de 512)
            offset: Offset en el dispositivo (debe ser multiplo de 512)

        Returns:
            Bytes leidos
        """
        SECTOR_SIZE = 512

        aligned_offset = (offset // SECTOR_SIZE) * SECTOR_SIZE
        offset_diff = offset - aligned_offset

        total_read = size + offset_diff
        aligned_size = ((total_read + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE

        kernel32 = ctypes.windll.kernel32
        high_offset = ctypes.c_long(aligned_offset >> 32)
        kernel32.SetFilePointer(
            self.handle,
            ctypes.c_long(aligned_offset & 0xFFFFFFFF),
            ctypes.byref(high_offset),
            FILE_BEGIN,
        )

        buffer = ctypes.create_string_buffer(aligned_size)
        bytes_read = ctypes.c_ulong(0)

        success = kernel32.ReadFile(
            self.handle,
            buffer,
            aligned_size,
            ctypes.byref(bytes_read),
            None,
        )

        if not success:
            raise RuntimeError(f"Error leyendo dispositivo: {ctypes.get_last_error()}")

        result = buffer.raw[:bytes_read.value]
        return result[offset_diff:offset_diff + size]

    def get_size(self) -> int:
        """Obtiene el tamano total del dispositivo."""
        kernel32 = ctypes.windll.kernel32
        file_size = ctypes.c_ulonglong(0)

        kernel32.GetFileSizeEx(
            self.handle,
            ctypes.byref(file_size),
        )

        return file_size.value

    def close(self):
        """Cierra el handle del dispositivo."""
        if self.handle and self.handle != INVALID_HANDLE_VALUE:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class StandardDeviceReader:
    """
    Lector estandar usando Python open().
    Fallback para cuando no se puede usar I/O nativo.
    """

    def __init__(self, device_path: str):
        self.device_path = device_path
        self.file = open(device_path, 'rb')

    def read_aligned(self, size: int, offset: int = 0) -> bytes:
        """Lee datos del dispositivo."""
        self.file.seek(offset)
        return self.file.read(size)

    def get_size(self) -> int:
        """Obtiene el tamano total."""
        self.file.seek(0, 2)
        return self.file.tell()

    def close(self):
        """Cierra el archivo."""
        if self.file:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_reader(device_path: str):
    """
    Crea el lector apropiado para la plataforma.

    En Windows, intenta usar I/O nativo. Si falla, usa estandar.
    """
    if sys.platform == 'win32':
        try:
            reader = NativeDeviceReader(device_path)
            print('[*] Usando I/O nativo Windows (NO_BUFFERING)')
            return reader
        except Exception as e:
            print(f'[WARNING] I/O nativo no disponible: {e}')
            print('[*] Usando I/O estandar')

    return StandardDeviceReader(device_path)


# ============================================================================
# 3. ESCANEO PARALELO
# ============================================================================

def _parallel_scan_worker(args):
    """
    Worker para escaneo paralelo.

    Cada worker escanea un chunk independiente del dispositivo.

    Args: (device_path, chunk_start, chunk_size, sig_names)
    Returns: Lista de (sig_name, file_bytes, absolute_offset)
    """
    device_path, chunk_start, chunk_size, sig_names = args

    results = []

    try:
        reader = create_reader(device_path)
        data = reader.read_aligned(chunk_size, chunk_start)
        reader.close()

        sigs = {k: FILE_SIGNATURES[k] for k in sig_names if k in FILE_SIGNATURES}
        searcher = MultiPatternSearcher(sigs)

        matches = searcher.search(data, base_offset=chunk_start)

        for sig_name, abs_offset in matches:
            sig = FILE_SIGNATURES[sig_name]
            footer = sig.get('footer')
            max_size = sig.get('max_size', 10 * 1024 * 1024)

            local_offset = abs_offset - chunk_start

            if footer:
                search_end = min(local_offset + max_size, len(data))
                footer_pos = data.find(footer, local_offset + 4, search_end)
                if footer_pos != -1:
                    file_size = footer_pos + len(footer) - local_offset
                else:
                    file_size = min(max_size, len(data) - local_offset)
            else:
                file_size = min(1024 * 1024, max_size, len(data) - local_offset)

            file_data = data[local_offset:local_offset + file_size]

            if len(file_data) > 100:
                results.append((sig_name, file_data, abs_offset))

    except Exception as e:
        pass  # Worker silencioso en caso de error

    return results


class ParallelScanner:
    """
    Escaneo paralelo del dispositivo.

    Divide el dispositivo en chunks y los escanea en paralelo usando
    ProcessPoolExecutor para aprovechar multiples nucleos de CPU.
    """

    def __init__(self, workers: int = None):
        import multiprocessing as mp
        self.workers = workers or mp.cpu_count()

    def scan_device(
        self,
        device_path: str,
        total_size: int,
        chunk_size: int = 1024 * 1024,
        offset_start: int = 0,
        types_filter: List[str] = None,
    ) -> List[Tuple[str, bytes, int]]:
        """
        Escanea el dispositivo en paralelo.

        Returns:
            Lista de (sig_name, file_data, absolute_offset)
        """
        # Preparar chunks
        chunks = []
        sig_names = list(FILE_SIGNATURES.keys())
        if types_filter:
            sig_names = [s for s in sig_names if s in types_filter or
                        FILE_SIGNATURES[s]['ext'].lstrip('.') in types_filter]

        offset = offset_start
        while offset < offset_start + total_size:
            current_chunk = min(chunk_size, offset_start + total_size - offset)
            chunks.append((device_path, offset, current_chunk, sig_names))
            offset += current_chunk

        print(f'[*] Escaneo paralelo: {len(chunks)} chunks en {self.workers} workers')

        all_results = []

        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(_parallel_scan_worker, chunk): chunk
                for chunk in chunks
            }

            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception:
                    pass

                if completed % 10 == 0 or completed == len(chunks):
                    print(f'\r[*] Progreso paralelo: {completed}/{len(chunks)} chunks',
                          end='', flush=True)

        print()
        return all_results


# ============================================================================
# 4. CACHE DE OFFSETS
# ============================================================================

class OffsetCache:
    """
    Cache de offsets encontrados para reescaneos rapidos.

    Guarda los offsets de archivos encontrados en un archivo JSON.
    En reescaneos, permite saltar zonas ya verificadas.
    """

    def __init__(self, cache_dir: str):
        self.cache_dir = Path(cache_dir)
        self.cache_file = self.cache_dir / '.scan_cache.json'
        self.data: Dict[str, List[Dict]] = self._load()

    def _load(self) -> Dict[str, List[Dict]]:
        """Carga cache desde disco."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def save(self):
        """Guarda cache a disco."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f'[WARNING] No se pudo guardar cache: {e}')

    def add_result(self, file_type: str, offset: int, size: int, file_hash: str):
        """Agrega un resultado encontrado al cache."""
        if file_type not in self.data:
            self.data[file_type] = []

        self.data[file_type].append({
            'offset': offset,
            'size': size,
            'hash': file_hash,
        })

    def get_scanned_ranges(self) -> List[Tuple[int, int]]:
        """
        Retorna rangos ya escaneados (offset, offset+size).

        Util para evitar re-escanear zonas conocidas.
        """
        ranges = []
        for entries in self.data.values():
            for entry in entries:
                start = entry['offset']
                end = start + entry['size']
                ranges.append((start, end))

        ranges.sort()
        return ranges

    def get_file_count(self) -> int:
        """Retorna total de archivos en cache."""
        return sum(len(entries) for entries in self.data.values())

    def clear(self):
        """Limpia el cache."""
        self.data = {}
        if self.cache_file.exists():
            self.cache_file.unlink()
