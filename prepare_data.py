import os
import numpy as np
from sklearn.model_selection import train_test_split
from tqdm import tqdm

# Paths
BENIGN_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Benign"
REAL_RANSOMWARE_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Ransomware\RealSamples"
SYNTHETIC_RANSOMWARE_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Ransomware\SimulatedSamples"
OUTPUT_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\ProcessedData"

MAX_FILE_SIZE = 100000
TRAIN_TEST_SPLIT = 0.2

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def read_file_bytes(filepath, max_bytes=MAX_FILE_SIZE):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(max_bytes)
        byte_array = np.frombuffer(data, dtype=np.uint8)
        if len(byte_array) < max_bytes:
            byte_array = np.pad(byte_array, (0, max_bytes - len(byte_array)), mode='constant')
        else:
            byte_array = byte_array[:max_bytes]
        return byte_array
    except:
        return None

def load_dataset():
    X, y = [], []
    
    print("\n=== LOADING DATASET ===\n")
    
    print("Loading benign files...")
    benign_files = [os.path.join(r, f) for r, _, files in os.walk(BENIGN_FOLDER) for f in files]
    print(f"Found {len(benign_files)} benign files")
    
    for fp in tqdm(benign_files[:4000], desc="Benign"):
        ba = read_file_bytes(fp)
        if ba is not None:
            X.append(ba)
            y.append(0)
    
    print("\nLoading real ransomware...")
    real_files = [os.path.join(r, f) for r, _, files in os.walk(REAL_RANSOMWARE_FOLDER) for f in files]
    print(f"Found {len(real_files)} real ransomware")
    
    for fp in tqdm(real_files, desc="Real ransomware"):
        ba = read_file_bytes(fp)
        if ba is not None:
            X.append(ba)
            y.append(1)
    
    print("\nLoading synthetic ransomware...")
    synth_files = [os.path.join(r, f) for r, _, files in os.walk(SYNTHETIC_RANSOMWARE_FOLDER) for f in files]
    print(f"Found {len(synth_files)} synthetic ransomware")
    
    for fp in tqdm(synth_files, desc="Synthetic"):
        ba = read_file_bytes(fp)
        if ba is not None:
            X.append(ba)
            y.append(1)
    
    X, y = np.array(X), np.array(y)
    print(f"\nTotal: {len(X)} samples (Benign: {sum(y==0)}, Ransomware: {sum(y==1)})")
    return X, y

def prepare_data():
    X, y = load_dataset()
    X = X.astype('float32') / 255.0
    X = X.reshape(-1, MAX_FILE_SIZE, 1)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TRAIN_TEST_SPLIT, random_state=42, stratify=y)
    
    print(f"\nTraining: {len(X_train)}, Testing: {len(X_test)}")
    print(f"Saving to {OUTPUT_FOLDER}...")
    
    np.save(os.path.join(OUTPUT_FOLDER, 'X_train.npy'), X_train)
    np.save(os.path.join(OUTPUT_FOLDER, 'X_test.npy'), X_test)
    np.save(os.path.join(OUTPUT_FOLDER, 'y_train.npy'), y_train)
    np.save(os.path.join(OUTPUT_FOLDER, 'y_test.npy'), y_test)
    
    print("\n✅ DATA READY!")

if __name__ == "__main__":
    prepare_data()