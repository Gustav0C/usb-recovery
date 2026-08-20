"""
Sistema de logging para escaneos.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class ScanLogger:
    """Registra eventos del escaneo a archivo."""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.log_file = self.output_dir / 'scan_log.json'
        self.entries: List[Dict] = []
        self.start_time = datetime.now()
    
    def log_event(self, event_type: str, data: Dict):
        """Registra un evento."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event_type,
            'data': data
        }
        self.entries.append(entry)
    
    def log_file_found(self, file_info: Dict):
        """Registra archivo encontrado."""
        self.log_event('file_found', {
            'filename': Path(file_info['path']).name,
            'type': file_info['type'],
            'size': file_info['size'],
            'offset': file_info['offset'],
            'hash': file_info.get('hash', ''),
        })
    
    def log_scan_start(self, device_path: str, config: Dict):
        """Registra inicio de escaneo."""
        self.log_event('scan_start', {
            'device': device_path,
            'config': config,
        })
    
    def log_scan_complete(self, stats: Dict):
        """Registra fin de escaneo."""
        self.log_event('scan_complete', {
            'duration_seconds': (datetime.now() - self.start_time).total_seconds(),
            **stats
        })
    
    def log_error(self, error: str, context: Dict = None):
        """Registra error."""
        self.log_event('error', {
            'message': error,
            'context': context or {},
        })
    
    def save(self):
        """Guarda el log a archivo."""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'version': '1.0',
                    'start_time': self.start_time.isoformat(),
                    'entries': self.entries
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f'[WARNING] No se pudo guardar log: {e}')
