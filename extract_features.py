import os
import numpy as np
from tqdm import tqdm
import math
from collections import Counter

BENIGN_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Benign"
REAL_RANSOMWARE_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Ransomware\RealSamples"
SYNTHETIC_RANSOMWARE_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Ransomware\SimulatedSamples"
OUTPUT_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\ProcessedData"

MAX_FILE_SIZE = 100000

def calculate_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    return entropy

def extract_features(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(MAX_FILE_SIZE)
        
        if len(data) == 0:
            return None
        
        # Byte histogram (256 features)
        byte_hist = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        byte_hist = byte_hist / len(data)
        
        # Entropy
        entropy = calculate_entropy(data)
        
        # File size
        file_size = len(data)
        
        # Printable ratio
        printable = sum(1 for b in data if 32 <= b <= 126)
        printable_ratio = printable / len(data)
        
        # Combine: 256 + 3 = 259 features
        features = np.concatenate([byte_hist, [entropy, file_size, printable_ratio]])
        return features
    except:
        return None

def load_and_extract():
    X, y = [], []
    
    print("\n=== EXTRACTING FEATURES ===\n")
    
    print("Processing benign files...")
    benign_files = [os.path.join(r, f) for r, _, files in os.walk(BENIGN_FOLDER) for f in files]
    print(f"Found {len(benign_files)} benign files")
    
    processed = 0
    for fp in tqdm(benign_files[:4000], desc="Benign"):
        features = extract_features(fp)
        if features is not None:
            X.append(features)
            y.append(0)
            processed += 1
    print(f"Successfully processed: {processed}/4000")
    
    print("\nProcessing real ransomware...")
    real_files = [os.path.join(r, f) for r, _, files in os.walk(REAL_RANSOMWARE_FOLDER) for f in files]
    print(f"Found {len(real_files)} real ransomware files")
    
    processed = 0
    for fp in tqdm(real_files, desc="Real ransomware"):
        features = extract_features(fp)
        if features is not None:
            X.append(features)
            y.append(1)
            processed += 1
    print(f"Successfully processed: {processed}/{len(real_files)}")
    
    print("\nProcessing synthetic ransomware...")
    synth_files = [os.path.join(r, f) for r, _, files in os.walk(SYNTHETIC_RANSOMWARE_FOLDER) for f in files]
    print(f"Found {len(synth_files)} synthetic ransomware files")
    
    processed = 0
    for fp in tqdm(synth_files, desc="Synthetic"):
        features = extract_features(fp)
        if features is not None:
            X.append(features)
            y.append(1)
            processed += 1
    print(f"Successfully processed: {processed}/{len(synth_files)}")
    
    X, y = np.array(X), np.array(y)
    
    print(f"\n=== FEATURE EXTRACTION COMPLETE ===")
    print(f"Total samples: {len(X)}")
    print(f"Benign: {sum(y==0)}")
    print(f"Ransomware: {sum(y==1)}")
    print(f"Feature dimensions: {X.shape}")
    
    print(f"\nSaving to {OUTPUT_FOLDER}...")
    np.save(os.path.join(OUTPUT_FOLDER, 'X_features.npy'), X)
    np.save(os.path.join(OUTPUT_FOLDER, 'y_labels.npy'), y)
    
    print("\n✅ FEATURES SAVED!")

if __name__ == "__main__":
    load_and_extract()