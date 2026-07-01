import math
import collections
from src.utils.logger import logger
from src.config import ENTROPY_CHECK_SAMPLES, MIN_FILE_SIZE_FOR_ENTROPY

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
            file_size = f.seek(0, 2)
            f.seek(0)

            if file_size < MIN_FILE_SIZE_FOR_ENTROPY:
                return 0.0
            
            sample_size = 1024
            sample_count = max(1, int(ENTROPY_CHECK_SAMPLES))

            if file_size <= sample_size * sample_count:
                data = f.read()
            else:
                chunks = []
                max_offset = file_size - sample_size
                for idx in range(sample_count):
                    offset = int((max_offset * idx) / max(sample_count - 1, 1))
                    f.seek(offset)
                    chunks.append(f.read(sample_size))
                data = b"".join(chunks)
                
        return calculate_shannon_entropy(data)
    except Exception as e:
        # logger.error(f"Error reading file for entropy {filepath}: {e}")
        return 0.0
