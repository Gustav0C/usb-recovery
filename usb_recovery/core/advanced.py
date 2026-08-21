"""
Features avanzadas para USB Recovery Tool.

- Modo forense con cadena de custodia
- Filtrado post-escaneo por fecha, tamaño, calidad
- Exportación a múltiples formatos (JSON, CSV, HTML, ZIP)
- Análisis forense detallado
"""

import os
import json
import csv
import zipfile
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod


# ============================================================================
# 1. MODO FORENSE (Solo Lectura + Cadena de Custodia)
# ============================================================================

@dataclass
class AuditEntry:
    """Entrada de auditoría para cadena de custodia."""
    timestamp: str
    device: str
    action: str
    details: str = ''
    hash: str = ''


@dataclass
class ForensicReport:
    """Reporte forense completo."""
    case_id: str
    examiner: str
    device_path: str
    device_info: Dict
    scan_start: str
    scan_end: str
    files_found: int
    total_size: int
    audit_log: List[AuditEntry] = field(default_factory=list)
    file_list: List[Dict] = field(default_factory=list)


class ForensicMode:
    """
    Modo forense con cadena de custodia.

    Registra cada acción realizada sobre el dispositivo para
    mantener la integridad de la evidencia.
    """

    def __init__(self, case_id: str = '', examiner: str = ''):
        self.case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.examiner = examiner
        self.audit_log: List[AuditEntry] = []
        self.start_time = datetime.now()

    def log_access(self, device_path: str, action: str, details: str = ''):
        """Registra acceso para cadena de custodia."""
        entry = AuditEntry(
            timestamp=datetime.now().isoformat(),
            device=device_path,
            action=action,
            details=details,
        )
        self.audit_log.append(entry)

    def calculate_file_hash(self, file_path: str) -> str:
        """Calcula hash SHA-256 de un archivo."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def generate_report(
        self,
        device_path: str,
        device_info: Dict,
        recovered_files: List[Dict],
    ) -> ForensicReport:
        """Genera reporte forense completo."""
        return ForensicReport(
            case_id=self.case_id,
            examiner=self.examiner,
            device_path=device_path,
            device_info=device_info,
            scan_start=self.start_time.isoformat(),
            scan_end=datetime.now().isoformat(),
            files_found=len(recovered_files),
            total_size=sum(f.get('size', 0) for f in recovered_files),
            audit_log=self.audit_log,
            file_list=recovered_files,
        )

    def export_report(self, report: ForensicReport, output_dir: str) -> str:
        """Exporta reporte forense a JSON."""
        output_path = Path(output_dir) / f"forensic_report_{self.case_id}.json"

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)

        return str(output_path)


# ============================================================================
# 2. FILTRADO POST-ESCANEO
# ============================================================================

class ScanFilter:
    """
    Filtra resultados de escaneo por múltiples criterios.

    Permite filtrar archivos encontrados por:
    - Tipo de archivo
    - Tamaño (min/max)
    - Offset (rango)
    - Calidad (para imágenes)
    - Fragmentación
    """

    def __init__(self, results: List[Dict]):
        self.results = results
        self._filtered = results.copy()

    def filter_by_type(self, types: List[str]) -> 'ScanFilter':
        """Filtra por tipo de archivo."""
        if not types:
            return self
        self._filtered = [
            r for r in self._filtered
            if r.get('type') in types or r.get('ext') in types
        ]
        return self

    def filter_by_size(self, min_size: int = 0, max_size: int = 0) -> 'ScanFilter':
        """Filtra por tamaño en bytes."""
        self._filtered = [
            r for r in self._filtered
            if min_size <= r.get('size', 0) <= (max_size or float('inf'))
        ]
        return self

    def filter_by_offset(self, start: int = 0, end: int = 0) -> 'ScanFilter':
        """Filtra por offset en el dispositivo."""
        self._filtered = [
            r for r in self._filtered
            if start <= r.get('offset', 0) <= (end or float('inf'))
        ]
        return self

    def filter_by_fragmentation(self, fragmented_only: bool = False) -> 'ScanFilter':
        """Filtra por estado de fragmentación."""
        if fragmented_only:
            self._filtered = [
                r for r in self._filtered
                if r.get('fragmented', False)
            ]
        return self

    def exclude_duplicates(self) -> 'ScanFilter':
        """Excluye duplicados por hash."""
        seen_hashes = set()
        unique = []
        for r in self._filtered:
            h = r.get('hash', '')
            if h and h not in seen_hashes:
                seen_hashes.add(h)
                unique.append(r)
            elif not h:
                unique.append(r)
        self._filtered = unique
        return self

    def get_results(self) -> List[Dict]:
        """Retorna resultados filtrados."""
        return self._filtered

    def get_stats(self) -> Dict:
        """Retorna estadísticas de los resultados filtrados."""
        if not self._filtered:
            return {'count': 0, 'total_size': 0, 'by_type': {}}

        by_type = {}
        total_size = 0
        for r in self._filtered:
            t = r.get('type', 'unknown')
            by_type[t] = by_type.get(t, 0) + 1
            total_size += r.get('size', 0)

        return {
            'count': len(self._filtered),
            'total_size': total_size,
            'total_size_mb': total_size / (1024 * 1024),
            'by_type': by_type,
        }


# ============================================================================
# 3. EXPORTACIÓN A MÚLTIPLES FORMATOS
# ============================================================================

class ExportManager:
    """
    Exporta resultados de escaneo en múltiples formatos.

    Soporta:
    - JSON (completo con metadata)
    - CSV (para Excel/herramientas de análisis)
    - HTML (reporte visual)
    - ZIP (archivos comprimidos)
    """

    def __init__(self, results: List[Dict], output_dir: str):
        self.results = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_json(self, filename: str = 'scan_results.json') -> str:
        """Exporta resultados a JSON."""
        output_path = self.output_dir / filename

        data = {
            'export_date': datetime.now().isoformat(),
            'total_files': len(self.results),
            'total_size': sum(r.get('size', 0) for r in self.results),
            'files': self.results,
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def export_csv(self, filename: str = 'scan_results.csv') -> str:
        """Exporta resultados a CSV."""
        output_path = self.output_dir / filename

        if not self.results:
            return str(output_path)

        # Obtener todas las claves únicas
        all_keys = set()
        for r in self.results:
            all_keys.update(r.keys())

        fieldnames = sorted(all_keys)

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)

        return str(output_path)

    def export_html(self, filename: str = 'scan_report.html') -> str:
        """Exporta reporte visual a HTML."""
        output_path = self.output_dir / filename

        # Estadísticas
        total_size = sum(r.get('size', 0) for r in self.results)
        by_type = {}
        for r in self.results:
            t = r.get('type', 'unknown')
            by_type[t] = by_type.get(t, 0) + 1

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>USB Recovery Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #2196F3; color: white; padding: 20px; border-radius: 8px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #2196F3; }}
        .stat-label {{ color: #666; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #2196F3; color: white; }}
        tr:hover {{ background: #f9f9f9; }}
        .type-badge {{ background: #E3F2FD; color: #1976D2; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>USB Recovery Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{len(self.results)}</div>
                <div class="stat-label">Files Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_size / (1024*1024):.1f} MB</div>
                <div class="stat-label">Total Size</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(by_type)}</div>
                <div class="stat-label">File Types</div>
            </div>
        </div>

        <h2>File Types Distribution</h2>
        <div class="stats">
"""

        for file_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
            html += f"""            <div class="stat-card">
                <div class="stat-value">{count}</div>
                <div class="stat-label">{file_type}</div>
            </div>
"""

        html += """        </div>

        <h2>Recovered Files</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Offset</th>
                    <th>Hash</th>
                    <th>Fragmented</th>
                </tr>
            </thead>
            <tbody>
"""

        for i, r in enumerate(self.results, 1):
            size_kb = r.get('size', 0) / 1024
            offset_hex = f"0x{r.get('offset', 0):08X}"
            frag = 'Yes' if r.get('fragmented') else 'No'
            hash_short = r.get('hash', '')[:12] + '...' if r.get('hash') else '-'

            html += f"""                <tr>
                    <td>{i}</td>
                    <td><span class="type-badge">{r.get('type', 'unknown')}</span></td>
                    <td>{size_kb:.1f} KB</td>
                    <td>{offset_hex}</td>
                    <td>{hash_short}</td>
                    <td>{frag}</td>
                </tr>
"""

        html += """            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return str(output_path)

    def export_to_zip(
        self,
        source_dir: str,
        filename: str = 'recovered_files.zip',
    ) -> str:
        """Exporta archivos recuperados a ZIP."""
        output_path = self.output_dir / filename
        source_path = Path(source_dir)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_info in self.results:
                file_path = file_info.get('path', '')
                if file_path and os.path.exists(file_path):
                    arcname = os.path.basename(file_path)
                    zf.write(file_path, arcname)

        return str(output_path)

    def export_metadata_only(self, filename: str = 'metadata.json') -> str:
        """Exporta solo metadata (sin archivos)."""
        metadata = []
        for r in self.results:
            meta = {
                'type': r.get('type'),
                'ext': r.get('ext'),
                'size': r.get('size'),
                'offset': r.get('offset'),
                'hash': r.get('hash'),
                'fragmented': r.get('fragmented'),
            }
            metadata.append(meta)

        output_path = self.output_dir / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        return str(output_path)


# ============================================================================
# 4. ANÁLISIS FORENSE DETALLADO
# ============================================================================

class ForensicAnalyzer:
    """
    Análisis forense detallado de archivos recuperados.

    Proporciona:
    - Detección de fragmentación
    - Estimación de integridad
    - Análisis de distribución en disco
    - Detección de sobreescritura parcial
    """

    def __init__(self, results: List[Dict], device_size: int = 0):
        self.results = results
        self.device_size = device_size

    def analyze_fragmentation(self) -> Dict:
        """Analiza patrones de fragmentación."""
        fragmented = [r for r in self.results if r.get('fragmented')]
        contiguous = [r for r in self.results if not r.get('fragmented')]

        # Calcular gaps entre archivos
        sorted_results = sorted(self.results, key=lambda x: x.get('offset', 0))
        gaps = []
        for i in range(1, len(sorted_results)):
            prev_end = sorted_results[i-1].get('offset', 0) + sorted_results[i-1].get('size', 0)
            curr_start = sorted_results[i].get('offset', 0)
            if curr_start > prev_end:
                gaps.append({
                    'from': prev_end,
                    'to': curr_start,
                    'size': curr_start - prev_end,
                })

        return {
            'total_files': len(self.results),
            'fragmented': len(fragmented),
            'contiguous': len(contiguous),
            'fragmentation_rate': len(fragmented) / len(self.results) if self.results else 0,
            'gaps': gaps,
            'total_gap_size': sum(g['size'] for g in gaps),
        }

    def analyze_distribution(self) -> Dict:
        """Analiza distribución de archivos en el dispositivo."""
        if not self.results or self.device_size == 0:
            return {}

        # Dividir dispositivo en zonas
        num_zones = 10
        zone_size = self.device_size // num_zones
        zones = [0] * num_zones

        for r in self.results:
            offset = r.get('offset', 0)
            zone = min(offset // zone_size, num_zones - 1)
            zones[zone] += r.get('size', 0)

        return {
            'device_size': self.device_size,
            'zone_size': zone_size,
            'zones': zones,
            'utilization': sum(zones) / self.device_size if self.device_size else 0,
        }

    def detect_overwrites(self) -> List[Dict]:
        """Detecta posibles sobreescrituras parciales."""
        overwrites = []

        for r in self.results:
            # Verificar si el archivo está cerca del inicio o fin
            offset = r.get('offset', 0)
            size = r.get('size', 0)

            # Archivos muy cerca del inicio pueden estar corruptos
            if offset < 1024:
                overwrites.append({
                    'file': r,
                    'reason': 'File at device start - may be partially overwritten',
                    'risk': 'high',
                })

            # Archivos sin footer完整 pueden estar truncados
            if r.get('truncated', False):
                overwrites.append({
                    'file': r,
                    'reason': 'File appears truncated',
                    'risk': 'medium',
                })

        return overwrites

    def generate_summary(self) -> Dict:
        """Genera resumen forense completo."""
        return {
            'total_files': len(self.results),
            'total_size': sum(r.get('size', 0) for r in self.results),
            'fragmentation': self.analyze_fragmentation(),
            'distribution': self.analyze_distribution(),
            'overwrites': self.detect_overwrites(),
            'integrity_estimate': self._estimate_integrity(),
        }

    def _estimate_integrity(self) -> Dict:
        """Estima integridad basada en análisis."""
        if not self.results:
            return {'score': 0, 'details': 'No files to analyze'}

        # Factores de integridad
        factors = []

        # 1. Archivos con hash válido
        with_hash = sum(1 for r in self.results if r.get('hash'))
        if with_hash > 0:
            factors.append(('hash_verified', with_hash / len(self.results)))

        # 2. Archivos no fragmentados
        contiguous = sum(1 for r in self.results if not r.get('fragmented'))
        if contiguous > 0:
            factors.append(('contiguous', contiguous / len(self.results)))

        # 3. Archivos no truncados
        not_truncated = sum(1 for r in self.results if not r.get('truncated'))
        if not_truncated > 0:
            factors.append(('not_truncated', not_truncated / len(self.results)))

        # Calcular score promedio
        if factors:
            score = sum(s for _, s in factors) / len(factors)
        else:
            score = 0.5

        return {
            'score': score,
            'grade': 'A' if score > 0.9 else 'B' if score > 0.7 else 'C' if score > 0.5 else 'D',
            'factors': factors,
        }
