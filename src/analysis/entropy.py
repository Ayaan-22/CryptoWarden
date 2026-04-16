import math
import collections
from src.utils.logger import logger

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon Entropy of a byte sequence.
    Returns a value between 0.0 and 8.0.
    """
    if not data:
        return 0.0
        
    entropy = 0
    length = len(data)
    counts = collections.Counter(data)
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def calculate_file_entropy(filepath: str) -> float:
    """
    Reads a file and calculates its entropy.
    Optimized to read chunks for large files.
    """
    try:
        with open(filepath, 'rb') as f:
            # Read first 1KB, Middle 1KB, and Last 1KB to approximate
            file_size = f.seek(0, 2)
            f.seek(0)
            
            if file_size < 3072: # Small file, read all
                data = f.read()
            else:
                # Sample beginning, middle, end
                head = f.read(1024)
                f.seek(file_size // 2)
                mid = f.read(1024)
                f.seek(file_size - 1024)
                tail = f.read(1024)
                data = head + mid + tail
                
        return calculate_shannon_entropy(data)
    except Exception as e:
        # logger.error(f"Error reading file for entropy {filepath}: {e}")
        return 0.0
