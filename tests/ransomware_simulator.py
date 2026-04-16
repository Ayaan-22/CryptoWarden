import os
import time
import random
import string
import secrets
from concurrent.futures import ThreadPoolExecutor

# Configuration
TEST_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "RansomwareTestArea")
NUM_FILES = 100 # Increase to ensure it runs for > 5 seconds

def create_dummy_files():
    if os.path.exists(TEST_DIR):
        # Cleanup
        for f in os.listdir(TEST_DIR):
            try:
                os.remove(os.path.join(TEST_DIR, f))
            except: pass
    else:
        os.makedirs(TEST_DIR)
    
    print(f"Creating {NUM_FILES} dummy files in {TEST_DIR}...")
    for i in range(NUM_FILES):
        filename = os.path.join(TEST_DIR, f"doc_{i}.txt")
        with open(filename, "w") as f:
            # Write some low entropy text
            f.write("This is a sensitive document. " * 50)
            
def encrypt_file(filepath):
    try:
        print(f"Encrypting {filepath}...")
        # Read content
        with open(filepath, "rb") as f:
            data = f.read()
        
        # Simulate Encryption (High Entropy)
        # Just write random bytes of same length
        encrypted_data = secrets.token_bytes(len(data))
        
        # Overwrite file
        with open(filepath, "wb") as f:
            f.write(encrypted_data)
            
        # Rename
        new_path = filepath + ".enc"
        os.rename(filepath, new_path)
        print(f"Renamed to {new_path}")
    except Exception as e:
        print(f"Failed to encrypt {filepath}: {e}")

def run_simulation():
    print("Starting Ransomware Simulation...")
    print(f"PID: {os.getpid()}")
    create_dummy_files()
    time.sleep(2) # Wait a bit
    
    files = [os.path.join(TEST_DIR, f) for f in os.listdir(TEST_DIR) if f.endswith(".txt")]
    
    # Rapidly encrypt files
    # We do it sequentially or parallel. Real ransomware is often threaded.
    # Let's simple loop to ensure PID is captured easily.
    for f in files:
        encrypt_file(f)
        time.sleep(0.05) # FAST! Should trigger rate limit.

    print("Simulation Complete. If I am still running, detection failed.")

if __name__ == "__main__":
    run_simulation()
