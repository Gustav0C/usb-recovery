#!/usr/bin/env python3
"""
USB File Recovery Tool - Interfaz TUI
======================================
Interfaz de terminal interactiva para recuperar archivos eliminados de USB.
"""

import os
import sys
import ctypes
import ctypes.wintypes
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable

# Importar el motor de carving
from usb_recovery import FileCarver, FILE_SIGNATURES
from usb_recovery.platform.detector import get_detector, DeviceInfo
from usb_recovery.utils.progress import ProgressBar


# ============================================================================
# COLORES ANSI
# ============================================================================

class Colors:
    """Colores ANSI para terminal."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Colores de texto
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Colores de fondo
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    @staticmethod
    def supports_color():
        """Verifica si la terminal soporta colores."""
        if os.name == 'nt':
            # Windows 10+ soporta colores ANSI
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except:
                return False
        return True


# ============================================================================
# UTILIDADES DE TERMINAL
# ============================================================================

def clear_screen():
    """Limpia la pantalla."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_terminal_size():
    """Obtiene el tamaño de la terminal."""
    try:
        import shutil
        cols, lines = shutil.get_terminal_size()
        return cols, lines
    except:
        return 80, 24


def print_centered(text: str, width: int = 60, color: str = ''):
    """Imprime texto centrado."""
    padding = (width - len(text)) // 2
    if padding < 0:
        padding = 0
    print(f"{' ' * padding}{color}{text}{Colors.RESET}")


def print_box(lines: List[str], width: int = 60, title: str = '', color: str = ''):
    """Imprime un cuadro con bordes."""
    if title:
        # Ajustar ancho para el título
        inner_width = width - 4
        if len(title) > inner_width:
            title = title[:inner_width-3] + '...'
        
        print(f"\n{color}┌{'─' * (width-2)}┐{Colors.RESET}")
        padding = (width - 4 - len(title)) // 2
        print(f"{color}│{Colors.RESET}{' ' * padding}{Colors.BOLD}{title}{' ' * (width - 4 - padding - len(title))}{Colors.RESET}{color}│{Colors.RESET}")
        print(f"{color}├{'─' * (width-2)}┤{Colors.RESET}")
    
    for line in lines:
        # Truncar si es muy largo
        if len(line) > width - 4:
            line = line[:width-7] + '...'
        
        padding = width - 4 - len(line)
        if padding < 0:
            padding = 0
        print(f"{color}│{Colors.RESET} {line}{' ' * padding} {color}│{Colors.RESET}")
    
    print(f"{color}└{'─' * (width-2)}┘{Colors.RESET}")


def print_separator(width: int = 60, char: str = '─', color: str = ''):
    """Imprime un separador."""
    print(f"{color}{char * width}{Colors.RESET}")


def print_header(title: str, width: int = 60):
    """Imprime un encabezado decorado."""
    clear_screen()
    print()
    print_centered("╔" + "═" * (width-2) + "╗", width, Colors.CYAN)
    print_centered(f"║{title:^{width-4}}║", width, Colors.CYAN + Colors.BOLD)
    print_centered("╚" + "═" * (width-2) + "╗", width, Colors.CYAN)
    print()


def input_option(prompt: str, options: List[str], width: int = 60) -> str:
    """Solicita una opción al usuario."""
    print()
    for i, option in enumerate(options, 1):
        print(f"  {Colors.CYAN}{i}.{Colors.RESET} {option}")
    print()
    
    while True:
        try:
            choice = input(f"{Colors.YELLOW}  Seleccione una opción (1-{len(options)}): {Colors.RESET}")
            choice = int(choice)
            if 1 <= choice <= len(options):
                return options[choice - 1]
        except ValueError:
            pass
        print(f"  {Colors.RED}Opción inválida. Intente de nuevo.{Colors.RESET}")


def input_yes_no(prompt: str, default: bool = True) -> bool:
    """Solicita confirmación sí/no."""
    default_text = "[S/n]" if default else "[s/N]"
    while True:
        try:
            choice = input(f"{Colors.YELLOW}  {prompt} {default_text}: {Colors.RESET}").lower()
            if choice == '':
                return default
            if choice in ('s', 'si', 'sí', 'yes', 'y'):
                return True
            if choice in ('n', 'no', 'not'):
                return False
        except (EOFError, KeyboardInterrupt):
            return default
        print(f"  {Colors.RED}Respuesta inválida. Use 's' o 'n'.{Colors.RESET}")


# ============================================================================
# CLASE PRINCIPAL TUI
# ============================================================================

class RecoveryTUI:
    """Interfaz TUI principal para recuperación USB."""
    
    def __init__(self):
        self.width = 60
        self.devices: List[DeviceInfo] = []
        self.selected_device: Optional[DeviceInfo] = None
        self.selected_types: List[str] = []
        self.output_dir: str = './recovered'
        self.scanning = False
        self.recovered_files: List[Dict] = []
        self.detector = get_detector()
    
    def show_banner(self):
        """Muestra el banner de inicio."""
        banner = [
            "  ╔═╗╦═╗╦ ╦╔═╗╔╦╗╔═╗  ╔═╗╦ ╦╔═╗╔╗╔╔╦╗",
            "  ╠═╝╠╦╝╚╦╝╠═╝ ║ ╠═╣  ╠═╣║ ║║ ║║║║ ║ ",
            "  ╩  ╩╚═ ╩ ╩   ╩ ╩ ╩  ╩ ╩╚═╝╚═╝╝╚╝ ╩ ",
        ]
        
        print_header("USB FILE RECOVERY TOOL", self.width)
        for line in banner:
            print_centered(line, self.width, Colors.GREEN + Colors.BOLD)
        print()
        print_centered("Recuperación de archivos eliminados", self.width, Colors.DIM)
        print_centered("Técnica: File Carving", self.width, Colors.DIM)
        print()
    
    def refresh_devices(self):
        """Refresca la lista de dispositivos USB."""
        print(f"\n{Colors.CYAN}[*] Buscando dispositivos USB...{Colors.RESET}")
        self.devices = self.detector.list_devices()
        
        if not self.devices:
            print(f"\n{Colors.YELLOW}[!] No se encontraron dispositivos USB.{Colors.RESET}")
            print(f"{Colors.DIM}    Asegúrese de que el USB esté conectado.{Colors.RESET}")
            return False
        
        print(f"{Colors.GREEN}[✓] Se encontraron {len(self.devices)} dispositivo(s){Colors.RESET}")
        time.sleep(0.5)
        return True
    
    def show_devices(self):
        """Muestra los dispositivos USB disponibles."""
        print_header("DISPOSITIVOS USB DETECTADOS", self.width)
        
        if not self.devices:
            print_box(
                ["No hay dispositivos conectados", " ", "Conecte un USB y seleccione 'Refrescar'"],
                self.width,
                "Sin dispositivos",
                Colors.YELLOW
            )
            return
        
        lines = []
        for i, dev in enumerate(self.devices, 1):
            # Barra de progreso visual
            bar_width = 20
            filled = int(bar_width * dev.used_percent / 100)
            bar = '█' * filled + '░' * (bar_width - filled)
            
            lines.append(f"{Colors.GREEN}{dev.id}{Colors.RESET} - {dev.name}")
            lines.append(f"  {Colors.DIM}Filesystem:{Colors.RESET} {dev.filesystem or 'desconocido'}")
            lines.append(f"  {Colors.DIM}Tamaño:{Colors.RESET} {dev.size_gb:.1f} GB")
            lines.append(f"  {Colors.DIM}Uso:{Colors.RESET} [{bar}] {dev.used_percent:.0f}%")
            lines.append(f"  {Colors.DIM}Libre:{Colors.RESET} {dev.free_gb:.1f} GB")
            if dev.model:
                lines.append(f"  {Colors.DIM}Modelo:{Colors.RESET} {dev.model}")
            if i < len(self.devices):
                lines.append("  ─────────────────────────────────────")
        
        print_box(lines, self.width, "USB Conectados", Colors.GREEN)
    
    def select_device(self) -> bool:
        """Permite al usuario seleccionar un dispositivo."""
        if not self.devices:
            print(f"\n{Colors.YELLOW}[!] No hay dispositivos para seleccionar.{Colors.RESET}")
            return False
        
        print()
        options = [f"{dev.id} - {dev.name}" for dev in self.devices]
        options.append("Cancelar")
        
        choice = input_option("Seleccione el dispositivo USB:", options, self.width)
        
        if choice == "Cancelar":
            return False
        
        # Encontrar el dispositivo seleccionado
        dev_id = choice.split(' - ')[0].strip()
        for dev in self.devices:
            if dev.id == dev_id:
                self.selected_device = dev
                print(f"\n{Colors.GREEN}[✓] Dispositivo seleccionado: {dev.id} - {dev.name}{Colors.RESET}")
                return True
        
        return False
    
    def show_file_types(self):
        """Muestra los tipos de archivo disponibles para filtrar."""
        print_header("TIPOS DE ARCHIVO", self.width)
        
        # Agrupar por categoría
        categories = {
            'Imágenes': ['jpeg', 'png', 'gif87', 'gif89', 'bmp', 'tiff', 'webp'],
            'Documentos': ['pdf', 'docx', 'xlsx', 'pptx'],
            'Comprimidos': ['zip', 'rar', '7z', 'gzip'],
            'Audio/Video': ['mp3', 'mp4', 'avi', 'mkv', 'wav'],
            'Otros': ['exe', 'elf'],
        }
        
        lines = []
        for category, types in categories.items():
            type_names = []
            for t in types:
                if t in FILE_SIGNATURES:
                    ext = FILE_SIGNATURES[t]['ext']
                    if t in self.selected_types:
                        type_names.append(f"{Colors.GREEN}✓{Colors.RESET}{ext}")
                    else:
                        type_names.append(f"{Colors.DIM}○{Colors.RESET}{ext}")
            
            lines.append(f"{Colors.CYAN}{category}:{Colors.RESET}")
            lines.append(f"  {' '.join(type_names)}")
        
        print_box(lines, self.width, "Formatos Soportados", Colors.CYAN)
    
    def select_file_types(self) -> bool:
        """Permite al usuario seleccionar tipos de archivo."""
        print_header("FILTRAR POR TIPO", self.width)
        
        options = [
            "Todos los tipos (recomendado)",
            "Solo imágenes (JPEG, PNG, GIF, BMP)",
            "Solo documentos (PDF, DOCX, XLSX, PPTX)",
            "Solo comprimidos (ZIP, RAR, 7z)",
            "Solo audio/video (MP3, MP4, AVI)",
            "Personalizar selección",
            "Cancelar"
        ]
        
        choice = input_option("¿Qué tipos de archivo desea recuperar?", options, self.width)
        
        if choice == "Cancelar":
            return False
        
        if "Todos" in choice:
            self.selected_types = []
            print(f"\n{Colors.GREEN}[✓] Se buscarán todos los tipos de archivo{Colors.RESET}")
        elif "imágenes" in choice.lower():
            self.selected_types = ['jpeg', 'png', 'gif87', 'gif89', 'bmp', 'tiff', 'webp']
            print(f"\n{Colors.GREEN}[✓] Se buscarán solo imágenes{Colors.RESET}")
        elif "documentos" in choice.lower():
            self.selected_types = ['pdf', 'docx', 'xlsx', 'pptx']
            print(f"\n{Colors.GREEN}[✓] Se buscarán solo documentos{Colors.RESET}")
        elif "comprimidos" in choice.lower():
            self.selected_types = ['zip', 'rar', '7z', 'gzip']
            print(f"\n{Colors.GREEN}[✓] Se buscarán solo comprimidos{Colors.RESET}")
        elif "audio" in choice.lower():
            self.selected_types = ['mp3', 'mp4', 'avi', 'mkv', 'wav']
            print(f"\n{Colors.GREEN}[✓] Se buscarán solo audio/video{Colors.RESET}")
        elif "Personalizar" in choice:
            if not self.custom_type_selection():
                return False
        
        return True
    
    def custom_type_selection(self) -> bool:
        """Selección personalizada de tipos de archivo."""
        print()
        print(f"{Colors.CYAN}Tipos disponibles:{Colors.RESET}")
        
        all_types = list(FILE_SIGNATURES.keys())
        for i, t in enumerate(all_types, 1):
            ext = FILE_SIGNATURES[t]['ext']
            marker = "✓" if t in self.selected_types else "○"
            print(f"  {i:2d}. [{marker}] {ext} ({t})")
        
        print()
        print(f"{Colors.DIM}Ingrese números separados por coma (ej: 1,2,5) o 'todos' para todo{Colors.RESET}")
        
        try:
            selection = input(f"{Colors.YELLOW}  Selección: {Colors.RESET}").strip()
            
            if selection.lower() == 'todos':
                self.selected_types = []
                return True
            
            indices = [int(x.strip()) for x in selection.split(',')]
            self.selected_types = [all_types[i-1] for i in indices if 1 <= i <= len(all_types)]
            
            if self.selected_types:
                print(f"\n{Colors.GREEN}[✓] Seleccionados: {', '.join(self.selected_types)}{Colors.RESET}")
                return True
            else:
                print(f"\n{Colors.RED}[!] No se seleccionó ningún tipo válido{Colors.RESET}")
                return False
        
        except (ValueError, IndexError):
            print(f"\n{Colors.RED}[!] Entrada inválida{Colors.RESET}")
            return False
    
    def select_output_dir(self) -> bool:
        """Selecciona directorio de salida."""
        print()
        print(f"{Colors.CYAN}Directorio de salida actual: {self.output_dir}{Colors.RESET}")
        
        if input_yes_no("¿Desea cambiar el directorio de salida?", False):
            try:
                new_dir = input(f"{Colors.YELLOW}  Ingrese la ruta: {Colors.RESET}").strip()
                if new_dir:
                    self.output_dir = new_dir
                    print(f"{Colors.GREEN}[✓] Directorio actualizado: {self.output_dir}{Colors.RESET}")
            except (EOFError, KeyboardInterrupt):
                pass
        
        return True
    
    def show_scan_summary(self):
        """Muestra resumen antes de escanear."""
        print_header("RESUMEN DEL ESCANEO", self.width)
        
        lines = [
            f"{Colors.GREEN}Dispositivo:{Colors.RESET} {self.selected_device.id} - {self.selected_device.name}",
            f"{Colors.GREEN}Ruta:{Colors.RESET} {self.selected_device.path}",
            f"{Colors.GREEN}Salida:{Colors.RESET} {self.output_dir}",
            f"{Colors.GREEN}Tipos:{Colors.RESET} {', '.join(self.selected_types) if self.selected_types else 'Todos'}",
            f"{Colors.GREEN}Tamaño:{Colors.RESET} {self.selected_device.size_gb:.1f} GB",
        ]
        
        print_box(lines, self.width, "Configuración", Colors.CYAN)
    
    def run_scan(self):
        """Ejecuta el escaneo del dispositivo."""
        print_header("ESCANEO EN PROGRESO", self.width)
        
        # Crear directorio de salida
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Obtener ruta raw del dispositivo
        device_path = self.detector.get_raw_path(self.selected_device.id)
        
        # Crear carver
        carver = FileCarver(
            device_path=device_path,
            output_dir=self.output_dir,
            chunk_size=1024 * 1024  # 1MB
        )
        
        self.scanning = True
        
        print(f"\n{Colors.CYAN}[*] Iniciando escaneo...{Colors.RESET}")
        print(f"{Colors.DIM}    Dispositivo: {device_path}{Colors.RESET}")
        print(f"{Colors.DIM}    Presione Ctrl+C para cancelar{Colors.RESET}\n")
        
        try:
            # Ejecutar escaneo
            self.recovered_files = carver.scan_device(
                types_filter=self.selected_types if self.selected_types else None,
                offset_start=0,
                max_size=None
            )
            
            self.show_scan_results()
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Escaneo cancelado por el usuario{Colors.RESET}")
            print(f"{Colors.DIM}    Archivos recuperados hasta el momento: {len(carver.recovered_files)}{Colors.RESET}")
        
        except Exception as e:
            print(f"\n{Colors.RED}[ERROR] Error durante el escaneo: {e}{Colors.RESET}")
        
        finally:
            self.scanning = False
        
        input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
    
    def show_scan_results(self):
        """Muestra los resultados del escaneo."""
        print()
        
        if not self.recovered_files:
            print_box(
                ["No se encontraron archivos eliminados.", " ", 
                 "El disco puede estar limpio o los datos fueron", "sobrescritos."],
                self.width,
                "Sin resultados",
                Colors.YELLOW
            )
            return
        
        # Estadísticas por tipo
        by_type = {}
        total_size = 0
        fragmented = 0
        for f in self.recovered_files:
            t = f['type']
            by_type[t] = by_type.get(t, 0) + 1
            total_size += f['size']
            if f.get('fragmented'):
                fragmented += 1
        
        lines = []
        lines.append(f"{Colors.GREEN}Total de archivos:{Colors.RESET} {len(self.recovered_files)}")
        lines.append(f"{Colors.GREEN}Espacio recuperado:{Colors.RESET} {total_size / (1024*1024):.1f} MB")
        if fragmented > 0:
            lines.append(f"{Colors.GREEN}Fragmentados:{Colors.RESET} {fragmented} reconstruidos")
        lines.append("")
        lines.append(f"{Colors.CYAN}Por tipo:{Colors.RESET}")
        
        for file_type, count in sorted(by_type.items()):
            ext = FILE_SIGNATURES[file_type]['ext']
            lines.append(f"  {ext}: {count} archivos")
        
        lines.append("")
        lines.append(f"{Colors.GREEN}Guardados en:{Colors.RESET} {self.output_dir}")
        
        print_box(lines, self.width, "Resultados", Colors.GREEN)
    
    def show_main_menu(self):
        """Muestra el menú principal."""
        print_header("MENÚ PRINCIPAL", self.width)
        
        # Estado actual
        if self.selected_device:
            status = [
                f"Dispositivo: {Colors.GREEN}{self.selected_device.id}{Colors.RESET} - {self.selected_device.name}",
                f"Tipos: {Colors.GREEN}{', '.join(self.selected_types) if self.selected_types else 'Todos'}{Colors.RESET}",
                f"Salida: {Colors.GREEN}{self.output_dir}{Colors.RESET}",
            ]
            print_box(status, self.width, "Configuración Actual", Colors.GREEN)
        
        options = [
            "🔄 Refrescar dispositivos USB",
            "📋 Ver dispositivos disponibles",
            "🎯 Seleccionar dispositivo USB",
            "📁 Filtrar por tipo de archivo",
            "📂 Cambiar directorio de salida",
            "▶️  INICIAR ESCANEO",
            "❌ Salir"
        ]
        
        print()
        for i, option in enumerate(options, 1):
            color = Colors.GREEN if i == 6 else Colors.WHITE
            if i == 7:
                color = Colors.RED
            print(f"  {Colors.CYAN}{i}.{Colors.RESET} {color}{option}{Colors.RESET}")
        
        print()
        while True:
            try:
                choice = input(f"{Colors.YELLOW}  Seleccione una opción (1-7): {Colors.RESET}")
                choice = int(choice)
                if 1 <= choice <= 7:
                    return choice
            except ValueError:
                pass
            print(f"  {Colors.RED}Opción inválida. Intente de nuevo.{Colors.RESET}")
    
    def run(self):
        """Bucle principal de la TUI."""
        try:
            # Habilitar colores en Windows
            Colors.supports_color()
            
            self.show_banner()
            
            # Cargar dispositivos iniciales
            self.refresh_devices()
            
            while True:
                choice = self.show_main_menu()
                
                if choice == 1:  # Refrescar
                    self.refresh_devices()
                    input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                
                elif choice == 2:  # Ver dispositivos
                    self.show_devices()
                    input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                
                elif choice == 3:  # Seleccionar dispositivo
                    self.select_device()
                    input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                
                elif choice == 4:  # Filtrar tipos
                    self.select_file_types()
                    input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                
                elif choice == 5:  # Directorio salida
                    self.select_output_dir()
                    input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                
                elif choice == 6:  # Iniciar escaneo
                    if not self.selected_device:
                        print(f"\n{Colors.YELLOW}[!] Primero debe seleccionar un dispositivo{Colors.RESET}")
                        input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                        continue
                    
                    self.show_scan_summary()
                    
                    if input_yes_no("¿Iniciar escaneo ahora?", True):
                        self.run_scan()
                    else:
                        print(f"\n{Colors.DIM}Escaneo cancelado{Colors.RESET}")
                        input(f"\n{Colors.DIM}Presione Enter para continuar...{Colors.RESET}")
                
                elif choice == 7:  # Salir
                    # Verificar si hay archivos recuperados sin revisar
                    if self.recovered_files:
                        print()
                        if not input_yes_no(
                            f"Hay {len(self.recovered_files)} archivo(s) recuperado(s). "
                            "¿Está seguro de salir?", False
                        ):
                            continue
                    
                    print()
                    print_box(
                        ["Gracias por usar USB File Recovery Tool", " ",
                         "Recuerde verificar los archivos recuperados", "y revisar su integridad."],
                        self.width,
                        "¡Hasta luego!",
                        Colors.GREEN
                    )
                    print()
                    break
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Saliendo...{Colors.RESET}")
            print()


# ============================================================================
# PUNTO DE ENTRADA
# ============================================================================

def main():
    """Función principal."""
    tui = RecoveryTUI()
    tui.run()


if __name__ == '__main__':
    main()
