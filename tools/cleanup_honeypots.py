import os
import sys

# Add the project root to sys.path so we can import config
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.config import MONITOR_DIRECTORIES
    from src.monitoring.honey_pot import HONEY_POT_FILENAMES
except ImportError:
    print("Error: Could not find CryptoWarden source. Please run this script from the project root.")
    sys.exit(1)

def cleanup():
    print("--- Starting Honey Pot Cleanup ---")
    count = 0
    for directory in MONITOR_DIRECTORIES:
        if not os.path.exists(directory):
            continue
            
        for filename in HONEY_POT_FILENAMES:
            file_path = os.path.join(directory, filename)
            if os.path.exists(file_path):
                try:
                    # Remove hidden attribute on Windows before deleting
                    if os.name == 'nt':
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(file_path, 128) # 128 = Normal
                    
                    os.remove(file_path)
                    print(f"  [DELETED] {file_path}")
                    count += 1
                except Exception as e:
                    print(f"  [ERROR] Failed to delete {file_path}: {e}")
    
    print(f"\nCleanup complete. Removed {count} files.")

if __name__ == "__main__":
    cleanup()
