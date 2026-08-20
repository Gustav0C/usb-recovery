# USB File Recovery Tool

Herramienta de Python para recuperar archivos eliminados de dispositivos USB mediante técnicas de **file carving** (talla de archivos).

## ⚠️ Advertencia Importante

- **Ejecute el script como administrador** para tener acceso raw al dispositivo
- **No escriba en el USB** después de borrar archivos (para evitar sobrescritura)
- Los archivos recuperados pueden estar parcialmente corruptos
- No es 100% garantizado - depende de si los bloques fueron reutilizados

## Requisitos

- Python 3.7+
- Windows (para detección automática de USB)
- Permisos de administrador

No requiere dependencias externas - solo usa la biblioteca estándar de Python.

## Uso

### 1. Listar dispositivos USB conectados

```bash
python usb_recovery.py --list-devices
```

### 2. Recuperar todos los archivos

```bash
python usb_recovery.py --device \\.\E: --output ./recuperados
```

### 3. Recuperar solo tipos específicos

```bash
python usb_recovery.py --device \\.\E: --output ./recuperados --types jpeg,pdf,png
```

### 4. Escanear una porción del dispositivo

```bash
python usb_recovery.py --device \\.\E: --output ./recuperados --offset 0 --size 1GB
```

## Tipos de Archivo Soportados

| Tipo | Extensión | Descripción |
|------|-----------|-------------|
| jpeg | .jpg | Imágenes JPEG |
| png | .png | Imágenes PNG |
| gif | .gif | Imágenes GIF |
| bmp | .bmp | Imágenes BMP |
| tiff | .tiff | Imágenes TIFF |
| webp | .webp | Imágenes WebP |
| pdf | .pdf | Documentos PDF |
| docx | .docx | Documentos Word |
| xlsx | .xlsx | Hojas de cálculo Excel |
| pptx | .pptx | Presentaciones PowerPoint |
| zip | .zip | Archivos comprimidos ZIP |
| rar | .rar | Archivos RAR |
| 7z | .7z | Archivos 7-Zip |
| gzip | .gz | Archivos GZIP |
| mp3 | .mp3 | Audio MP3 |
| mp4 | .video | Video MP4 |
| avi | .avi | Video AVI |
| mkv | .mkv | Video MKV |
| wav | .wav | Audio WAV |
| exe | .exe | Ejecutables Windows |
| elf | .elf | Ejecutables Linux |

## Opciones de Línea de Comandos

```
--device, -d       Ruta del dispositivo (ej: \\.\E:)
--output, -o       Directorio de salida (default: ./recovered)
--list-devices, -l Listar dispositivos USB conectados
--types, -t        Tipos de archivo a buscar (separados por coma)
--offset           Offset inicial de escaneo en bytes
--size, -s         Tamaño máximo a escaneo (ej: 1GB, 500MB)
--chunk-size       Tamaño de bloque de lectura (default: 1MB)
```

## Ejemplo Práctico

```bash
# 1. Conectar el USB y verlo
python usb_recovery.py --list-devices

# 2. Recuperar todo del USB (suponiendo que es E:)
python usb_recovery.py --device \\.\E: --output ./mi_usb_recuperado

# 3. Verificar archivos recuperados
dir mi_usb_recuperado
```

## Cómo Funciona

1. **Apertura raw**: Accede al dispositivo directamente a nivel de sector
2. **Escaneo por firmas**: Busca secuencias de bytes que identifican cada tipo de archivo
3. **Extracción**: Extrae los datos desde la cabecera hasta el footer del archivo
4. **Guardado**: Escribe los archivos recuperados en el directorio de salida

## Limitaciones

- **No recupera nombres de archivo originales** (solo genera nombres genéricos)
- **No recupera estructura de carpetas**
- **Archivos fragmentados** pueden no recuperarse correctamente
- **Archivos pequeños** (<100 bytes) se ignoran para evitar falsos positivos
- **No funciona con cifrado** (BitLocker, Veracrypt, etc.)

## Consejos

1. **Actuar rápido**: Cuanto antes, mejor - los bloques se reutilizan
2. **No usar el USB**: Evitar escribir datos nuevos
3. **Ejecutar como administrador**: Necesario para acceso raw
4. **Probar con tipos específicos**: Si solo buscás fotos, usar `--types jpeg,png`
5. **Revisar manualmente**: Algunos archivos pueden estar corruptos

## Licencia

Uso bajo su responsabilidad. Esta herramienta es para recuperación legítima de datos propios.
