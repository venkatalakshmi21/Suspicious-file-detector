from pathlib import Path
import hashlib


def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """Return the SHA-256 hash of a file without executing it."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_file(file_path):
    """Collect basic static information about a file."""
    path = Path(file_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(file_path)

    if not path.is_file():
        raise IsADirectoryError(file_path)

    absolute_path = path.resolve()
    size_bytes = path.stat().st_size

    return {
        "file_name": path.name,
        "absolute_path": str(absolute_path),
        "extension": path.suffix.lower(),
        "size_bytes": size_bytes,
        "size_kb": size_bytes / 1024,
        "sha256": calculate_sha256(path),
    }
