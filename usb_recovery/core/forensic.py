"""
Motor forense avanzado.

Características:
- Overlap dinámico por tipo de archivo (no pierde firmas entre chunks)
- Reconstrucción de archivos fragmentados
- Búsqueda eficiente con pre-filtrado por cabecera
- Soporte para archivos multi-chunk
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from pathlib import Path
from datetime import datetime

from .signatures import FILE_SIGNATURES


# ============================================================================
# OVERLAP DINÁMICO
# ============================================================================

# Tamaño de overlap necesario por tipo para no perder firmas entre chunks.
# JPEG y PNG tienen cabeceras pequeñas pero pueden tener información crítica
# al inicio que necesita contexto. ZIP necesita leer el local header completo.
DYNAMIC_OVERLAP: Dict[str, int] = {
    # Imágenes - cabeceras pequeñas
    'jpeg': 4,
    'png': 8,
    'gif87': 6,
    'gif89': 6,
    'bmp': 14,
    'tiff': 8,
    'webp': 12,

    # Documentos
    'pdf': 1024,       # %%EOF puede estar lejos del final
    'docx': 30,        # PK header + offset field
    'xlsx': 30,
    'pptx': 30,

    # Comprimidos - necesitan leer el local file header completo
    'zip': 30,
    'rar': 16,
    '7z': 32,
    'gzip': 18,

    # Audio/Video
    'mp3': 14,         # ID3 tag puede ser grande, pero el header es 10 bytes
    'mp4': 32,         # ftyp box completo
    'avi': 12,
    'mkv': 16,
    'wav': 12,

    # Ejecutables
    'exe': 64,
    'elf': 64,
}

# Overlap mínimo global para capturar cualquier firma que cruze chunks
MIN_OVERLAP = 8192


def get_dynamic_overlap(sig_name: str) -> int:
    """Retorna el overlap dinámico para un tipo de archivo."""
    return max(DYNAMIC_OVERLAP.get(sig_name, 8), MIN_OVERLAP)


# ============================================================================
# ESTRUCTURAS DE DATOS
# ============================================================================

@dataclass
class FileCandidate:
    """Candidato a archivo recuperado antes de validación final."""
    sig_name: str
    ext: str
    offset: int
    size: int
    data: bytes
    hash: str = ''
    is_fragmented: bool = False
    chunk_count: int = 1

    def __post_init__(self):
        if not self.hash:
            self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Hash rápido basado en muestra."""
        if len(self.data) <= 8192:
            return hashlib.md5(self.data).hexdigest()

        # Hash de inicio + medio + final
        h = hashlib.md5()
        h.update(self.data[:4096])
        h.update(self.data[len(self.data)//2 : len(self.data)//2 + 2048])
        h.update(self.data[-2048:])
        return h.hexdigest()


@dataclass
class FragmentInfo:
    """Información de un fragmento parcial encontrado."""
    sig_name: str
    offset: int
    expected_size: int
    found_size: int
    data: bytes
    is_complete: bool = False


@dataclass
class ScanResult:
    """Resultado del escaneo forense."""
    files_found: List[FileCandidate] = field(default_factory=list)
    fragments: List[FragmentInfo] = field(default_factory=list)
    duplicates_skipped: int = 0
    invalid_skipped: int = 0
    bytes_scanned: int = 0
    errors: int = 0


# ============================================================================
# MOTOR FORENSE
# ============================================================================

class ForensicEngine:
    """
    Motor de carving forense avanzado.

    Mejoras sobre el carver básico:
    1. Overlap dinámico por tipo de archivo
    2. Pre-filtrado rápido antes de extraer
    3. Detección de fragmentos parciales
    4. Reconstrucción básica de archivos fragmentados
    """

    def __init__(self):
        self.candidates: Dict[str, List[FileCandidate]] = {}
        self.fragments: List[FragmentInfo] = []
        self.seen_hashes: Dict[str, str] = {}  # hash -> file_path

    def compute_overlap(self, sig_name: str) -> int:
        """Calcula el overlap necesario para un tipo de archivo."""
        return get_dynamic_overlap(sig_name)

    def find_signatures_in_chunk(
        self,
        data: bytes,
        signatures: Dict[str, Dict],
        base_offset: int = 0,
    ) -> List[Tuple[str, Dict, int]]:
        """
        Busca todas las firmas en un chunk de datos.

        Returns:
            Lista de (sig_name, signature_dict, offset_abs)
        """
        matches = []

        for sig_name, sig in signatures.items():
            header = sig.get('header')
            if not header:
                continue

            header_len = len(header)
            pos = 0

            while pos <= len(data) - header_len:
                # Búsqueda rápida de la cabecera
                idx = data.find(header, pos)
                if idx == -1:
                    break

                # Verificación adicional para firmas compuestas
                if self._verify_signature(data, sig, idx):
                    matches.append((sig_name, sig, base_offset + idx))

                pos = idx + 1

        # Ordenar por offset para procesar en orden
        matches.sort(key=lambda x: x[2])
        return matches

    def _verify_signature(self, data: bytes, sig: Dict, offset: int) -> bool:
        """Verificación completa de una firma incluyendo campos secundarios."""
        header = sig.get('header', b'')

        # Verificar cabecera principal
        if data[offset:offset + len(header)] != header:
            return False

        # Verificar check_offset/check_bytes (ej: WebP, MP4, WAV, AVI)
        if 'check_offset' in sig and 'check_bytes' in sig:
            check_pos = offset + sig['check_offset']
            check_end = check_pos + len(sig['check_bytes'])
            if check_end > len(data):
                return False
            if data[check_pos:check_end] != sig['check_bytes']:
                return False

        # Verificar header2 (ej: JPEG EXIF, TIFF big-endian)
        if 'header2' in sig:
            if data[offset:offset + len(sig['header2'])] == sig['header2']:
                return True
            # Si no coincide header2, verificar que al menos coincida header principal
            # (ya lo verificamos arriba)

        # Verificar check_content para ZIP-based (DOCX, XLSX, PPTX)
        if 'check_content' in sig:
            # Necesitamos leer más datos para verificar el contenido interno
            check_range = min(offset + 4096, len(data))
            chunk = data[offset:check_range]
            if sig['check_content'] not in chunk:
                return False

        return True

    def extract_file(
        self,
        data: bytes,
        offset: int,
        sig: Dict,
        sig_name: str,
        total_device_size: int,
    ) -> Optional[FileCandidate]:
        """
        Intenta extraer un archivo completo desde los datos.

        Returns:
            FileCandidate si se extrajo correctamente, None si falla
        """
        ext = sig['ext']
        max_size = sig.get('max_size', 10 * 1024 * 1024)

        # Calcular tamaño del archivo
        file_size = self._calculate_size(data, sig, offset, max_size)

        if file_size is None:
            # No se pudo determinar el tamaño - marcar como fragmento
            self._record_fragment(sig_name, offset, -1, data, False)
            return None

        if file_size < 16:
            return None

        # Extraer datos
        end = min(offset + file_size, len(data))
        file_data = data[offset:end]

        # Verificar que no sea todo ceros
        if self._is_all_zeros(file_data):
            return None

        # Verificar tamaño mínimo por tipo
        if not self._check_minimum_size(file_data, ext):
            return None

        # Determinar si el archivo está incompleto
        is_fragmented = (offset + file_size > len(data)) and (end < total_device_size)

        return FileCandidate(
            sig_name=sig_name,
            ext=ext,
            offset=offset,
            size=len(file_data),
            data=file_data,
            is_fragmented=is_fragmented,
        )

    def _calculate_size(
        self,
        data: bytes,
        sig: Dict,
        offset: int,
        max_size: int,
    ) -> Optional[int]:
        """Calcula el tamaño del archivo buscando footer o usando máximos."""
        footer = sig.get('footer')

        if footer is None:
            # Sin footer: usar tamaño razonable basado en tipo
            # Para archivos sin footer, intentar leer un bloque razonable
            default_size = min(1024 * 1024, max_size)  # 1MB default
            return min(default_size, len(data) - offset)

        # Buscar footer
        search_start = offset + 4
        search_end = min(offset + max_size, len(data))

        footer_pos = data.find(footer, search_start, search_end)

        if footer_pos != -1:
            return footer_pos + len(footer) - offset

        # Footer no encontrado en esta ventana
        # Puede ser que el archivo continúe en el siguiente chunk
        if offset + max_size > len(data):
            return None  # Señal de que puede estar fragmentado

        return None

    def _record_fragment(
        self,
        sig_name: str,
        offset: int,
        expected_size: int,
        data: bytes,
        is_complete: bool,
    ):
        """Registra un fragmento parcial encontrado."""
        self.fragments.append(FragmentInfo(
            sig_name=sig_name,
            offset=offset,
            expected_size=expected_size,
            found_size=len(data),
            data=data,
            is_complete=is_complete,
        ))

    @staticmethod
    def _is_all_zeros(data: bytes) -> bool:
        """Verifica si los datos son todo ceros."""
        if len(data) < 256:
            return all(b == 0 for b in data)
        # Muestrear primeros, medios y últimos 256 bytes
        sample = data[:256] + data[len(data)//2:len(data)//2+256] + data[-256:]
        return all(b == 0 for b in sample)

    @staticmethod
    def _check_minimum_size(data: bytes, ext: str) -> bool:
        """Verifica tamaño mínimo razonable por tipo."""
        minimums = {
            '.jpg': 100,
            '.jpeg': 100,
            '.png': 67,       # Cabecera PNG mínimo
            '.gif': 30,
            '.bmp': 54,
            '.pdf': 100,
            '.docx': 200,
            '.xlsx': 200,
            '.pptx': 200,
            '.zip': 100,
            '.rar': 100,
            '.7z': 32,
            '.mp3': 256,
            '.mp4': 100,
            '.avi': 100,
            '.mkv': 100,
            '.wav': 100,
            '.exe': 1024,
        }
        min_size = minimums.get(ext, 50)
        return len(data) >= min_size

    def deduplicate(self, candidate: FileCandidate) -> bool:
        """
        Verifica si un candidato es duplicado.

        Returns:
            True si es duplicado (debe omitirse)
        """
        if candidate.hash in self.seen_hashes:
            return True
        self.seen_hashes[candidate.hash] = ''
        return False

    def try_reassemble_fragments(self) -> List[FileCandidate]:
        """
        Intenta reconstruir archivos a partir de fragmentos parciales.

        Estrategia:
        1. Agrupar fragmentos por tipo de archivo
        2. Ordenar por offset
        3. Unir fragmentos contiguos o cercanos
        4. Validar el resultado

        Returns:
            Lista de archivos reconstruidos
        """
        if not self.fragments:
            return []

        # Agrupar por tipo
        by_type: Dict[str, List[FragmentInfo]] = {}
        for frag in self.fragments:
            by_type.setdefault(frag.sig_name, []).append(frag)

        reassembled = []

        for sig_name, frags in by_type.items():
            sig = FILE_SIGNATURES.get(sig_name)
            if not sig:
                continue

            # Ordenar por offset
            frags.sort(key=lambda f: f.offset)

            # Intentar unir fragmentos cercanos (gap < 8KB)
            groups = self._group_close_fragments(frags, max_gap=8192)

            for group in groups:
                if len(group) < 2:
                    continue

                # Concatenar datos de fragmentos
                combined = b''
                for frag in group:
                    combined += frag.data

                # Verificar que el resultado combinado sea válido
                ext = sig['ext']
                if len(combined) >= self._check_minimum_size(combined, ext):
                    candidate = FileCandidate(
                        sig_name=sig_name,
                        ext=ext,
                        offset=group[0].offset,
                        size=len(combined),
                        data=combined,
                        is_fragmented=True,
                        chunk_count=len(group),
                    )

                    if not self.deduplicate(candidate):
                        reassembled.append(candidate)

        return reassembled

    @staticmethod
    def _group_close_fragments(
        frags: List[FragmentInfo],
        max_gap: int,
    ) -> List[List[FragmentInfo]]:
        """Agrupa fragmentos que están cerca unos de otros."""
        if not frags:
            return []

        groups: List[List[FragmentInfo]] = [[frags[0]]]

        for frag in frags[1:]:
            last_group = groups[-1]
            last_frag = last_group[-1]

            gap = frag.offset - (last_frag.offset + last_frag.found_size)

            if gap <= max_gap:
                last_group.append(frag)
            else:
                groups.append([frag])

        return groups


# ============================================================================
# SCAN COORDINATOR
# ============================================================================

class ForensicScanCoordinator:
    """
    Coordina el escaneo forense completo.

    Maneja:
    - Lectura del dispositivo con overlap dinámico
    - Búsqueda de firmas
    - Extracción de archivos
    - Validación
    - Deduplicación
    - Reconstrucción de fragmentos
    """

    def __init__(self, chunk_size: int = 1024 * 1024):
        self.chunk_size = chunk_size
        self.engine = ForensicEngine()

    def scan_chunk(
        self,
        data: bytes,
        base_offset: int,
        signatures: Dict[str, Dict],
        total_device_size: int,
    ) -> List[FileCandidate]:
        """
        Escanea un chunk de datos buscando archivos.

        Args:
            data: Datos del chunk (incluyendo overlap del chunk anterior)
            base_offset: Offset real del inicio de estos datos en el dispositivo
            signatures: Firmas de archivos a buscar
            total_device_size: Tamaño total del dispositivo

        Returns:
            Lista de candidatos encontrados en este chunk
        """
        found = []

        # Buscar todas las firmas en el chunk
        matches = self.engine.find_signatures_in_chunk(data, signatures, base_offset)

        for sig_name, sig, abs_offset in matches:
            # Extraer archivo
            candidate = self.engine.extract_file(
                data=data,
                offset=abs_offset - base_offset,  # Offset relativo al chunk
                sig=sig,
                sig_name=sig_name,
                total_device_size=total_device_size,
            )

            if candidate is None:
                continue

            # Ajustar offset absoluto
            candidate.offset = abs_offset

            # Verificar duplicados
            if self.engine.deduplicate(candidate):
                continue

            found.append(candidate)

        return found

    def finalize(self) -> Tuple[List[FileCandidate], List[FragmentInfo]]:
        """
        Finaliza el escaneo y retorna resultados.

        Returns:
            (archivos_encontrados, fragmentos_parciales)
        """
        # Intentar reconstruir fragmentos
        reassembled = self.engine.try_reassemble_fragments()

        # Agregar reconstruidos a la lista final
        all_files = self.engine.candidates.get('final', [])
        all_files.extend(reassembled)

        return all_files, self.engine.fragments
