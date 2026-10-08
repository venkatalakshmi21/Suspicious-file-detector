from pathlib import Path
import hashlib
from datetime import datetime

DOCUMENT_EXTENSIONS={".pdf",".txt",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".csv"}
IMAGE_EXTENSIONS={".jpg",".jpeg",".png",".gif",".bmp",".webp"}
VIDEO_EXTENSIONS={".mp4",".avi",".mkv",".mov",".wmv"}
ARCHIVE_EXTENSIONS={".zip",".rar",".7z",".tar",".gz"}
SCRIPT_EXTENSIONS={".py",".js",".vbs",".ps1",".bat",".cmd"}
EXECUTABLE_EXTENSIONS={".exe",".msi",".scr",".com"}
FILE_SIGNATURES={
    b"%PDF-":("PDF document",".pdf"),
    b"\x89PNG\r\n\x1a\n":("PNG image",".png"),
    b"\xff\xd8\xff":("JPEG image",".jpg"),
    b"GIF87a":("GIF image",".gif"),
    b"GIF89a":("GIF image",".gif"),
    b"PK\x03\x04":("ZIP-based/archive file",".zip"),
    b"MZ":("Windows PE/executable family",".exe"),
}

def calculate_sha256(file_path, chunk_size=1024*1024):
    sha256=hashlib.sha256()
    with open(file_path,"rb") as file:
        while True:
            chunk=file.read(chunk_size)
            if not chunk: break
            sha256.update(chunk)
    return sha256.hexdigest()

def analyze_extension(extension):
    extension=extension.lower()
    if not extension: return "No extension","Unknown"
    if extension in EXECUTABLE_EXTENSIONS: return "Executable","Review carefully"
    if extension in SCRIPT_EXTENSIONS: return "Script","Review carefully"
    if extension in DOCUMENT_EXTENSIONS: return "Document","Normal document type"
    if extension in IMAGE_EXTENSIONS: return "Image","Normal image type"
    if extension in VIDEO_EXTENSIONS: return "Video","Normal video type"
    if extension in ARCHIVE_EXTENSIONS: return "Archive","Review contents before opening"
    return "Other","Unknown file type"

def detect_double_extension(file_name):
    parts=Path(file_name).name.split(".")
    if len(parts)<3: return False,[]
    extensions=["."+part.lower() for part in parts[1:] if part]
    return len(extensions)>=2,extensions

def detect_signature(file_path):
    with open(file_path,"rb") as file: header=file.read(16)
    for signature,(file_type,expected_extension) in FILE_SIGNATURES.items():
        if header.startswith(signature): return file_type,expected_extension
    return "Unknown signature",None

def analyze_file(file_path):
    path=Path(file_path).expanduser()
    if not path.exists(): raise FileNotFoundError(file_path)
    if not path.is_file(): raise IsADirectoryError(file_path)
    stat_info=path.stat(); extension=path.suffix.lower()
    category,extension_indicator=analyze_extension(extension)
    double_extension,detected_extensions=detect_double_extension(path.name)
    signature_type,signature_extension=detect_signature(path)
    if signature_extension is None: signature_match="Unknown"
    elif extension==signature_extension: signature_match="MATCH"
    else: signature_match="MISMATCH"
    indicators=[]
    if double_extension: indicators.append("Possible double extension detected")
    if category in {"Executable","Script"}: indicators.append(f"Executable/script extension detected: {extension}")
    if signature_match=="MISMATCH": indicators.append(f"File extension {extension or '[none]'} does not match detected signature type ({signature_type})")
    if signature_type=="Unknown signature": indicators.append("File signature could not be identified")
    return {
        "file_name":path.name,"absolute_path":str(path.resolve()),"extension":extension,
        "size_bytes":stat_info.st_size,"size_kb":stat_info.st_size/1024,
        "modified_time":datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "extension_category":category,"extension_indicator":extension_indicator,
        "double_extension":double_extension,"detected_extensions":detected_extensions,
        "signature_type":signature_type,"signature_match":signature_match,
        "indicators":indicators,"sha256":calculate_sha256(path)
    }
