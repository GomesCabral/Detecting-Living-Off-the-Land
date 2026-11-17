from pathlib import Path
 
 
MAX_FILE_SIZE = 10 * 1024 * 1024
 
ALLOWED_EXTENSIONS = {".csv", ".json"}
 
 
def validate_file(file):
    if file is None:
        raise ValueError("No file provided.")
 
    if hasattr(file, "name"):
        filename = file.name
    else:
        filename = str(file)
 
    extension = Path(filename).suffix.lower()
 
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension: {extension}"
        )
 
    if hasattr(file, "size"):
        file_size = file.size
 
    elif hasattr(file, "getbuffer"):
        file_size = len(file.getbuffer())
 
    else:
        file_size = Path(file).stat().st_size
 
    if file_size == 0:
        raise ValueError("The file is empty.")
 
    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            "File exceeds the 10 MB size limit."
        )
 
    return extension
