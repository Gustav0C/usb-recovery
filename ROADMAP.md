# 🗺️ USB Recovery Tool - Roadmap de Mejoras

## Visión
Convertir la herramienta en una solución **profesional de nivel forense** con rendimiento óptimo, validación robusta y UX moderna.

---

## 📊 Resumen de Fases

| Fase | Nombre | Prioridad | Tiempo Est. | Dependencias |
|------|--------|-----------|-------------|--------------|
| 0 | Core Foundation | 🔴 Crítica | 2-3 días | Ninguna |
| 1 | Motor Forense | 🔴 Crítica | 4-5 días | Fase 0 |
| 2 | Rendimiento | 🟠 Alta | 3-4 días | Fase 1 |
| 3 | Multiplataforma | 🟠 Alta | 2-3 días | Fase 0 |
| 4 | UX/UI Premium | 🟡 Media | 4-5 días | Fase 1 |
| 5 | Features Avanzadas | 🟡 Media | 3-4 días | Fase 2, 4 |
| 6 | Empaquetado | 🟢 Baja | 1-2 días | Todas |

**Tiempo total estimado: 19-26 días**

---

## 🔴 Fase 0: Core Foundation (2-3 días)

### Objetivo
Establecer la arquitectura base para todas las mejoras.

### Tareas

#### 0.1 Arquitectura Modular
```
usb_recovery/
├── __init__.py
├── core/
│   ├── __init__.py
│   ├── carver.py          # Motor de carving (actual FileCarver)
│   ├── signatures.py      # Firmas de archivos
│   ├── device.py          # Abstracción de dispositivos
│   └── validator.py       # Validación de integridad
├── platform/
│   ├── __init__.py
│   ├── windows.py         # Detección Windows
│   ├── linux.py           # Detección Linux
│   └── darwin.py          # Detección macOS
├── ui/
│   ├── __init__.py
│   ├── cli.py             # CLI actual
│   ├── tui.py             # TUI actual
│   └── gui.py             # Futura GUI (opcional)
├── utils/
│   ├── __init__.py
│   ├── progress.py        # Barras de progreso
│   ├── logging.py         # Sistema de logs
│   └── config.py          # Configuración
└── main.py                # Punto de entrada unificado
```

#### 0.2 Sistema de Configuración
```python
# config.py
@dataclass
class ScanConfig:
    device_path: str
    output_dir: str
    types_filter: List[str]
    max_size: Optional[int]
    chunk_size: int = 1024 * 1024
    parallel_workers: int = 4
    validate_integrity: bool = True
    save_progress: bool = True
```

#### 0.3 Sistema de Logging
- Logs a archivo con rotación
- Niveles: DEBUG, INFO, WARNING, ERROR
- Exportable a JSON

### Criterio de Aceptación
- [ ] Estructura de carpetas creada
- [ ] Configuración centralizada funcional
- [ ] Logging básico implementado
- [ ] Tests unitarios base

---

## 🔴 Fase 1: Motor Forense (4-5 días)

### Objetivo
Implementar carving profesional con validación y manejo de fragmentación.

### Tareas

#### 1.1 Carving por Bloques con Overlap
```python
# Problema actual: buffer de 8 bytes pierde firmas
# Solución: overlap dinámico basado en tamaño de firma máxima

MAX_SIGNATURE_SIZE = 32  # bytes
OVERLAP_SIZE = MAX_SIGNATURE_SIZE * 2  # 64 bytes mínimo

# Mejor: overlap configurable por tipo de archivo
OVERLAPS = {
    'jpeg': 4,      # Solo cabecera
    'png': 8,       # Cabecera + magic
    'zip': 30,      # Needs local header parse
    'pdf': 1024,    # Buscar %%EOF en ventana amplia
}
```

#### 1.2 Validación de Integridad
```python
class FileValidator:
    """Valida integridad de archivos recuperados."""
    
    def validate_jpeg(self, data: bytes) -> ValidationResult:
        """Valida estructura JPEG completa."""
        # 1. Verificar SOI marker (FFD8)
        # 2. Buscar EOI marker (FFD9)
        # 3. Verificar markers intermedios
        # 4. Opcional: intentar decodificar con PIL
        
    def validate_pdf(self, data: bytes) -> ValidationResult:
        """Valida estructura PDF."""
        # 1. Verificar cabecera %PDF
        # 2. Buscar %%EOF
        # 3. Verificar xref table
        # 4. Opcional: validar con PyPDF2
    
    def validate_zip(self, data: bytes) -> ValidationResult:
        """Valida estructura ZIP."""
        # 1. Verificar local file headers
        # 2. Verificar central directory
        # 3. Verificar end of central directory
```

#### 1.3 Reconstrucción de Fragmentos
```python
class FragmentReconstructor:
    """Reconstruye archivos fragmentados."""
    
    def __init__(self, fragment_size: int = 4096):
        self.fragment_size = fragment_size
        self.fragment_map: Dict[int, Fragment] = {}
    
    def add_fragment(self, offset: int, data: bytes, file_type: str):
        """Agrega un fragmento encontrado."""
        
    def try_reassemble(self) -> List[ReassembledFile]:
        """Intenta reconstruir archivos a partir de fragmentos."""
        # 1. Agrupar fragmentos por tipo
        # 2. Ordenar por offset
        # 3. Detectar gaps
        # 4. Reconstruir si gap < umbral
```

#### 1.4 Deduplicación
```python
class FileDeduplicator:
    """Elimina archivos duplicados."""
    
    def __init__(self):
        self.hash_map: Dict[str, List[FileInfo]] = {}
    
    def add_file(self, file_path: str, offset: int) -> bool:
        """Agrega archivo, retorna True si es nuevo."""
        # Calcular hash (MD5 o xxHash para velocidad)
        # Comparar con existentes
        # Mantener solo el más completo
```

### Criterio de Aceptación
- [ ] Overlap dinámico implementado
- [ ] Validación para top 10 formatos
- [ ] Detección de fragmentación básica
- [ ] Deduplicación por hash
- [ ] Tests con archivos corruptos

---

## 🟠 Fase 2: Rendimiento (3-4 días)

### Objetivo
Alcanzar >100 MB/s de escaneo con I/O optimizado.

### Tareas

#### 2.1 Búsqueda Multi-Patrón (Aho-Corasick)
```python
# Problema: buscar cada firma secuencialmente es O(n*m)
# Solución: Aho-Corasick es O(n + z) donde z = coincidencias

import ahocorasick  # pip install pyahocorasick

class MultiPatternSearcher:
    def __init__(self):
        self.automaton = ahocorasick.Automaton()
        self._build_automaton()
    
    def _build_automaton(self):
        for sig_name, sig in FILE_SIGNATURES.items():
            self.automaton.add_word(sig['header'], (sig_name, 'header'))
            if 'header2' in sig:
                self.automaton.add_word(sig['header2'], (sig_name, 'header2'))
        self.automaton.make_automaton()
    
    def search(self, data: bytes) -> List[Match]:
        matches = []
        for end_idx, (sig_name, match_type) in self.automaton.iter(data):
            start_idx = end_idx - len(data) + 1
            matches.append(Match(sig_name, start_idx, match_type))
        return matches
```

#### 2.2 I/O Nativo Windows (CreateFile)
```python
import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000

class NativeDeviceReader:
    def __init__(self, device_path: str):
        self.handle = kernel32.CreateFileW(
            device_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
            None
        )
    
    def read(self, size: int, offset: int) -> bytes:
        # Seek + Read con overlapped I/O
        pass
```

#### 2.3 Escaneo Paralelo
```python
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp

class ParallelCarver:
    def __init__(self, workers: int = None):
        self.workers = workers or mp.cpu_count()
    
    def scan_parallel(self, device_path: str, chunks: List[ChunkRange]) -> List[FileInfo]:
        """Divide el disco en chunks y escanea en paralelo."""
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self._scan_chunk, device_path, chunk): chunk
                for chunk in chunks
            }
            
            results = []
            for future in as_completed(futures):
                results.extend(future.result())
            
            return results
```

#### 2.4 Caché de Offsets
```python
class OffsetCache:
    """Guarda offsets encontrados para reescaneos rápidos."""
    
    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self.offsets: Dict[str, List[int]] = {}
    
    def save(self):
        """Persiste caché a disco."""
        with open(self.cache_file, 'w') as f:
            json.dump(self.offsets, f)
    
    def get_candidates(self, file_type: str) -> List[int]:
        """Retorna offsets candidatos para un tipo."""
        return self.offsets.get(file_type, [])
```

### Criterio de Aceptación
- [ ] Aho-Corasick integrado
- [ ] I/O nativo para Windows
- [ ] Escaneo paralelo funcional
- [ ] Benchmark: >100 MB/s en SSD
- [ ] Caché de offsets persistente

---

## 🟠 Fase 3: Multiplataforma (2-3 días)

### Objetivo
Soporte completo para Windows, Linux y macOS.

### Tareas

#### 3.1 Abstracción de Dispositivos
```python
# device.py
from abc import ABC, abstractmethod

class DeviceDetector(ABC):
    @abstractmethod
    def list_devices(self) -> List[DeviceInfo]:
        pass
    
    @abstractmethod
    def get_raw_path(self, device_id: str) -> str:
        pass

class WindowsDetector(DeviceDetector):
    def list_devices(self) -> List[DeviceInfo]:
        # Implementación actual
        pass

class LinuxDetector(DeviceDetector):
    def list_devices(self) -> List[DeviceInfo]:
        # /proc/partitions + /sys/block
        # lsblk parsing
        pass

class DarwinDetector(DeviceDetector):
    def list_devices(self) -> List[DeviceInfo]:
        # diskutil list
        pass
```

#### 3.2 Lector de Dispositivos Universal
```python
class DeviceReader:
    """Lee de dispositivos de forma cross-platform."""
    
    def __init__(self, device_path: str, platform: str = None):
        self.platform = platform or sys.platform
        self._init_reader()
    
    def _init_reader(self):
        if self.platform == 'win32':
            self._reader = WindowsNativeReader()
        elif self.platform == 'linux':
            self._reader = LinuxRawReader()
        elif self.platform == 'darwin':
            self._reader = DarwinRawReader()
```

#### 3.3 Detección Auto de Plataforma
```python
def get_platform() -> str:
    if sys.platform == 'win32':
        return 'windows'
    elif sys.platform == 'darwin':
        return 'macos'
    elif sys.platform.startswith('linux'):
        return 'linux'
    else:
        raise UnsupportedPlatform(sys.platform)
```

### Criterio de Aceptación
- [ ] Detección en las 3 plataformas
- [ ] Lector nativo por plataforma
- [ ] Tests en CI/CD multiplatform
- [ ] Documentación de instalación por OS

---

## 🟡 Fase 4: UX/UI Premium (4-5 días)

### Objetivo
Interfaz moderna con preview, navegación por teclado y feedback visual.

### Tareas

#### 4.1 Preview de Archivos
```python
class FilePreview:
    """Genera preview de archivos recuperados."""
    
    def generate_thumbnail(self, file_path: str, size: Tuple[int, int] = (128, 128)) -> Optional[Image]:
        """Genera thumbnail para imágenes."""
        try:
            from PIL import Image
            img = Image.open(file_path)
            img.thumbnail(size)
            return img
        except:
            return None
    
    def get_metadata(self, file_path: str) -> Dict:
        """Extrae metadata del archivo."""
        ext = Path(file_path).suffix.lower()
        
        if ext in ('.jpg', '.jpeg', '.png', '.gif'):
            return self._get_image_metadata(file_path)
        elif ext == '.pdf':
            return self._get_pdf_metadata(file_path)
        elif ext in ('.mp3', '.wav'):
            return self._get_audio_metadata(file_path)
        
        return {}
```

#### 4.2 Navegación por Teclado
```python
class KeyboardNavigator:
    """Navegación con flechas y atajos."""
    
    SHORTCUTS = {
        'up': ['k', '\x1b[A'],      # k o flecha arriba
        'down': ['j', '\x1b[B'],    # j o flecha abajo
        'select': ['\r', ' '],      # Enter o espacio
        'back': ['\x1b[D', 'q'],    # Flecha izquierda o q
        'quit': ['\x03', '\x1b[C'], # Ctrl+C o flecha derecha
    }
    
    def get_input(self) -> str:
        """Captura tecla presionada."""
        if sys.platform == 'win32':
            import msvcrt
            return msvcrt.getch()
        else:
            import tty, termios
            # Implementación Unix
            pass
```

#### 4.3 Temas de Color
```python
class ThemeManager:
    """Gestiona temas de color."""
    
    THEMES = {
        'dark': {
            'bg': '#1e1e1e',
            'fg': '#d4d4d4',
            'accent': '#569cd6',
            'success': '#4ec9b0',
            'warning': '#dcdcaa',
            'error': '#f44747',
        },
        'light': {
            'bg': '#ffffff',
            'fg': '#000000',
            'accent': '#0000ff',
            'success': '#008000',
            'warning': '#ff8c00',
            'error': '#ff0000',
        },
        'matrix': {
            'bg': '#000000',
            'fg': '#00ff00',
            'accent': '#00ff00',
            'success': '#00ff00',
            'warning': '#ffff00',
            'error': '#ff0000',
        }
    }
    
    def detect_theme(self) -> str:
        """Detecta tema de la terminal."""
        # Verificar variables de entorno
        # Verificar configuración del terminal
        # Fallback a 'dark'
```

#### 4.4 Barra de Progreso Mejorada
```python
class ProgressBar:
    """Barra de progreso con ETA y velocidad."""
    
    def update(self, current: int, total: int, **kwargs):
        """
        Actualiza barra con:
        - Porcentaje
        - Velocidad (MB/s)
        - ETA (tiempo estimado)
        - Archivos encontrados
        - Barra visual con colores
        """
        percent = current / total * 100
        speed = kwargs.get('speed', 0)
        eta = (total - current) / speed if speed > 0 else 0
        
        bar_width = 40
        filled = int(bar_width * percent / 100)
        
        # Barra con degradado
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Colores por progreso
        if percent < 30:
            color = Colors.RED
        elif percent < 70:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN
        
        print(f'\r{color}[{bar}] {percent:.1f}% '
              f'| {speed:.1f} MB/s '
              f'| ETA: {eta:.0f}s '
              f'| Found: {kwargs.get("found", 0)}', 
              end='', flush=True)
```

#### 4.5 Log Exportable
```python
class ScanLogger:
    """Registra y exporta logs del escaneo."""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.log_file = self.output_dir / 'scan_log.json'
        self.entries: List[LogEntry] = []
    
    def log_file_found(self, file_info: FileInfo):
        self.entries.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'file_found',
            'data': asdict(file_info)
        })
    
    def export_json(self):
        with open(self.log_file, 'w') as f:
            json.dump(self.entries, f, indent=2)
    
    def export_csv(self):
        # Exportar a CSV para Excel
        pass
```

### Criterio de Aceptación
- [ ] Preview de imágenes funcional
- [ ] Navegación completa con teclado
- [ ] 3 temas de color
- [ ] Progreso con ETA y velocidad
- [ ] Log exportable a JSON/CSV

---

## 🟡 Fase 5: Features Avanzadas (3-4 días)

### Objetivo
Funcionalidades profesionales y diferenciadoras.

### Tareas

#### 5.1 Modo Forense (Solo Lectura)
```python
class ForensicMode:
    """Modo forense con cadena de custodia."""
    
    def __init__(self):
        self.audit_log = []
        self.evidence_chain = []
    
    def log_access(self, device_path: str, action: str):
        """Registra acceso para cadena de custodia."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'device': device_path,
            'action': action,
            'hash': self._calculate_hash(),
        }
        self.audit_log.append(entry)
    
    def generate_report(self) -> ForensicReport:
        """Genera reporte forense completo."""
        pass
```

#### 5.2 Recuperación Selectiva Post-Escaneo
```python
class SelectiveRecovery:
    """Permite recuperar archivos específicos después del escaneo."""
    
    def __init__(self, scan_results: List[FileInfo]):
        self.results = scan_results
        self.selected: List[FileInfo] = []
    
    def filter_by_size(self, min_size: int, max_size: int) -> List[FileInfo]:
        pass
    
    def filter_by_date(self, start: datetime, end: datetime) -> List[FileInfo]:
        pass
    
    def filter_by_quality(self, min_quality: float) -> List[FileInfo]:
        """Filtra por calidad estimada (para imágenes)."""
        pass
```

#### 5.3 Exportación Múltiple
```python
class ExportManager:
    """Exporta resultados en múltiples formatos."""
    
    def export_to_zip(self, files: List[FileInfo], output: str):
        pass
    
    def export_to_tar(self, files: List[FileInfo], output: str):
        pass
    
    def export_metadata_only(self, files: List[FileInfo], output: str):
        """Exporta solo metadata (útil para revisión)."""
        pass
```

#### 5.4 Integración con Herramientas Externas
```python
class ExternalToolsIntegration:
    """Integra con herramientas forenses externas."""
    
    def run_testdisk(self, device_path: str):
        """Ejecuta testdisk para recuperación de particiones."""
        pass
    
    def run_photorec(self, device_path: str, file_types: List[str]):
        """Ejecuta photoRec para carving avanzado."""
        pass
    
    def export_to_autopsy(self, results: List[FileInfo]):
        """Exporta en formato compatible con Autopsy."""
        pass
```

### Criterio de Aceptación
- [ ] Modo forense con auditoría
- [ ] Filtrado post-escaneo
- [ ] Exportación a ZIP/TAR
- [ ] Integración con testdisk/photoRec

---

## 🟢 Fase 6: Empaquetado y Distribución (1-2 días)

### Objetivo
Facilitar instalación y distribución.

### Tareas

#### 6.1 Instalador Universal
```bash
# Windows
installer/usb-recovery-setup.exe

# macOS
brew install usb-recovery

# Linux
sudo apt install usb-recovery  # Debian/Ubuntu
sudo pacman -S usb-recovery    # Arch
```

#### 6.2 PyPI Package
```python
# setup.py
from setuptools import setup

setup(
    name='usb-recovery-pro',
    version='2.0.0',
    packages=['usb_recovery'],
    install_requires=[
        'Pillow>=9.0',      # Para thumbnails
        'rich>=12.0',       # Para UI mejorada
    ],
    entry_points={
        'console_scripts': [
            'usb-recovery=usb_recovery.main:main',
        ],
    },
)
```

#### 6.3 Contenedor Docker
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -e .

# Para escaneo de dispositivos USB
# docker run --privileged -v /dev:/dev usb-recovery
```

#### 6.4 Documentación
- README con screenshots
- Guía de instalación por plataforma
- Ejemplos de uso
- Troubleshooting
- Contributing guidelines

### Criterio de Aceptación
- [ ] Package PyPI funcional
- [ ] Instalador Windows
- [ ] Docker image
- [ ] Documentación completa

---

## 📈 Métricas de Éxito

### Rendimiento
- [ ] Escaneo >100 MB/s en SSD
- [ ] Escaneo >50 MB/s en HDD
- [ ] Uso de CPU <50% en escaneo paralelo
- [ ] Memoria <500 MB para discos de 1TB

### Calidad
- [ ] Tasa de recuperación >80% para archivos contiguos
- [ ] Tasa de falsos positivos <1%
- [ ] Validación de integridad para top 10 formatos

### UX
- [ ] Tiempo de inicio <2 segundos
- [ ] Feedback visual en cada operación
- [ ] Navegación completa sin mouse

---

## 🎯 Quick Wins (Mejoras Rápidas)

Estas mejoras se pueden implementar en <1 día cada una:

1. **Aumentar overlap a 8KB** - Evita perder firmas
2. **Agregar hash xxHash** - Deduplicación rápida
3. **Log a archivo** - Registro de escaneos
4. **Confirmación de salida** - Evita perder progreso
5. **Validación JPEG básica** - Detectar archivos corruptos

---

## 📋 Notas de Implementación

### Dependencias Recomendadas
```requirements.txt
# Core
Pillow>=9.0          # Thumbnails de imágenes
xxhash>=3.0          # Hashing rápido
pyahocorasick>=1.4   # Búsqueda multi-patrón

# UI
rich>=12.0           # UI enriquecida
blessed>=1.20        # TUI alternativa

# Forense (opcional)
python-magic>=0.4    # Detección de tipo MIME
PyPDF2>=3.0          # Validación PDF
pyewf>=2021          # Format EWF (opcional)
```

### Testing
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Performance benchmarks
pytest tests/benchmark/ --benchmark-only

# Multiplatform CI
.github/workflows/ci.yml
```

---

## 🚀 Próximos Pasos Inmediatos

1. **Crear estructura de carpetas** (Fase 0.1)
2. **Implementar config.py** (Fase 0.2)
3. **Agregar logging** (Fase 0.3)
4. **Mejorar overlap** (Quick Win #1)
5. **Agregar validación JPEG** (Quick Win #5)

¿Quieres que comience con la Fase 0 o prefieres que implemente los Quick Wins primero?
