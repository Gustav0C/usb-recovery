"""
Barra de progreso mejorada con ETA y velocidad.
"""

import sys
import time
from typing import Optional


class ProgressBar:
    """Barra de progreso con ETA, velocidad y información detallada."""
    
    def __init__(self, total: int, prefix: str = '', suffix: str = ''):
        """
        Args:
            total: Total de unidades
            prefix: Prefijo de la barra
            suffix: Sufijo de la barra
        """
        self.total = total
        self.current = 0
        self.prefix = prefix
        self.suffix = suffix
        self.start_time = time.time()
        self.last_update = self.start_time
        self.found = 0
        self.bar_width = 40
    
    def update(self, n: int = 1, found: int = 0):
        """
        Actualiza la barra de progreso.
        
        Args:
            n: Unidades a avanzar
            found: Archivos encontrados (opcional)
        """
        self.current += n
        self.found += found
        
        now = time.time()
        # Actualizar como máximo 10 veces por segundo
        if now - self.last_update < 0.1:
            return
        
        self.last_update = now
        self._print()
    
    def _print(self):
        """Imprime la barra de progreso."""
        if self.total == 0:
            return
        
        percent = min(self.current / self.total * 100, 100)
        elapsed = time.time() - self.start_time
        
        # Velocidad
        if elapsed > 0:
            speed = self.current / elapsed
        else:
            speed = 0
        
        # ETA
        if speed > 0 and self.current < self.total:
            remaining = (self.total - self.current) / speed
            eta = self._format_time(remaining)
        else:
            eta = '--:--'
        
        # Barra visual
        filled = int(self.bar_width * percent / 100)
        bar = '█' * filled + '░' * (self.bar_width - filled)
        
        # Colores por progreso
        if percent < 30:
            color = '\033[31m'  # Rojo
        elif percent < 70:
            color = '\033[33m'  # Amarillo
        else:
            color = '\033[32m'  # Verde
        
        reset = '\033[0m'
        
        # Formatear velocidad
        if speed > 1024 * 1024:
            speed_str = f'{speed / (1024*1024):.1f} MB/s'
        elif speed > 1024:
            speed_str = f'{speed / 1024:.1f} KB/s'
        else:
            speed_str = f'{speed:.0f} B/s'
        
        # Imprimir
        sys.stdout.write(
            f'\r{color}{self.prefix}[{bar}] {percent:.1f}%{reset} '
            f'| {speed_str} '
            f'| ETA: {eta} '
            f'| Found: {self.found} '
            f'{self.suffix}'
        )
        sys.stdout.flush()
    
    def _format_time(self, seconds: float) -> str:
        """Formatea tiempo en MM:SS o HH:MM:SS."""
        if seconds < 0:
            return '--:--'
        
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f'{hours:02d}:{minutes:02d}:{secs:02d}'
        else:
            return f'{minutes:02d}:{secs:02d}'
    
    def finish(self):
        """Finaliza la barra de progreso."""
        self.current = self.total
        self._print()
        print()  # Nueva línea
