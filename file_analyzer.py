from pathlib import Path
import hashlib
from datetime import datetime

DOCUMENT_EXTENSIONS = {".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".wmv"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
SCRIPT_EXTENSIONS = {".py", ".js", ".vbs", ".ps1", ".bat", ".cmd"}
EXECUTABLE_EXTENSIONS = {".exe", ".msi", ".scr", ".com"}

def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """Calculate SHA-256 without executing the file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def analyze_extension(extension):
    extension = extension.lower()
    if not extension:
        return "No extension", "Unknown"
    if extension in EXECUTABLE_EXTENSIONS:
        return "Executable", "Review carefully"
    if extension in SCRIPT_EXTENSIONS:
        return "Script", "Review carefully"
    if extension in DOCUMENT_EXTENSIONS:
        return "Document", "Normal document type"
    if extension in IMAGE_EXTENSIONS:
        return "Image", "Normal image type"
    if extension in VIDEO_EXTENSIONS:
        return "Video", "Normal video type"
    if extension in ARCHIVE_EXTENSIONS:
        return "Archive", "Review contents before opening"
    return "Other", "Unknown file type"

def analyze_file(file_path):
    path = Path(file_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(file_path)
    if not path.is_file():
        raise IsADirectoryError(file_path)

    absolute_path = path.resolve()
    stat_info = path.stat()
    extension = path.suffix.lower()
    category, indicator = analyze_extension(extension)

    return {
        "file_name": path.name,
        "absolute_path": str(absolute_path),
        "extension": extension,
        "size_bytes": stat_info.st_size,
        "size_kb": stat_info.st_size / 1024,
        "modified_time": datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "extension_category": category,
        "extension_indicator": indicator,
        "sha256": calculate_sha256(path),
    }
