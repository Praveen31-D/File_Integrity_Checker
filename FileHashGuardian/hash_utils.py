import hashlib

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate hash of a file using specified algorithm."""
    hash_functions = {
        'sha256': hashlib.sha256,
        'md5': hashlib.md5,
        'sha1': hashlib.sha1
    }
    
    hash_func = hash_functions.get(algorithm, hashlib.sha256)()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        raise Exception(f"Error calculating hash: {str(e)}")
