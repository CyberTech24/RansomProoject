import os
import random
import numpy as np
from tqdm import tqdm
import shutil

# Configuration
REAL_RANSOMWARE_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Ransomware\RealSamples"
OUTPUT_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Ransomware\SimulatedSamples"
NUM_SAMPLES = 2000
MAX_FILE_SIZE = 500000  # 500KB max per sample

# Create output folder
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def read_file_bytes(filepath, max_bytes=MAX_FILE_SIZE):
    """Read file as bytes (limited size)"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(max_bytes)
        return np.frombuffer(data, dtype=np.uint8)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

def analyze_ransomware_pattern(byte_array):
    """Extract pattern characteristics from ransomware"""
    if byte_array is None or len(byte_array) == 0:
        return None
    
    return {
        'byte_freq': np.bincount(byte_array, minlength=256),
        'length': len(byte_array),
        'entropy': calculate_entropy(byte_array)
    }

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0
    
    byte_counts = np.bincount(data, minlength=256)
    probabilities = byte_counts[byte_counts > 0] / len(data)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

def generate_synthetic_sample(base_patterns, target_size):
    """Generate synthetic ransomware-like data based on real patterns"""
    # Choose random base pattern
    pattern = random.choice(base_patterns)
    
    if pattern is None:
        return None
    
    # Get byte frequency distribution from real ransomware
    byte_freq = pattern['byte_freq']
    
    # Normalize to probabilities
    byte_probs = byte_freq / byte_freq.sum()
    
    # Generate new byte sequence using same distribution
    synthetic_bytes = np.random.choice(
        256, 
        size=min(target_size, pattern['length']), 
        p=byte_probs
    )
    
    # Add some noise/variation (5-10% of bytes)
    noise_indices = np.random.choice(
        len(synthetic_bytes), 
        size=int(len(synthetic_bytes) * 0.07),
        replace=False
    )
    synthetic_bytes[noise_indices] = np.random.randint(0, 256, size=len(noise_indices))
    
    return synthetic_bytes.astype(np.uint8)

def apply_ransomware_transformations(byte_array, pattern):
    """Apply transformations mimicking ransomware behavior"""
    # Chunk shuffling (ransomware often encrypts in chunks)
    chunk_size = 1024  # 1KB chunks
    chunks = [byte_array[i:i+chunk_size] for i in range(0, len(byte_array), chunk_size)]
    
    # Randomly shuffle some chunks (simulates block encryption)
    if len(chunks) > 2:
        num_shuffle = random.randint(1, min(5, len(chunks)//2))
        shuffle_indices = random.sample(range(len(chunks)), num_shuffle)
        for idx in shuffle_indices:
            np.random.shuffle(chunks[idx])
    
    # Recombine
    result = np.concatenate(chunks)
    
    # Ensure high entropy (ransomware characteristic)
    target_entropy = pattern['entropy']
    current_entropy = calculate_entropy(result)
    
    # If entropy too low, add more randomness
    if current_entropy < target_entropy * 0.9:
        random_indices = np.random.choice(
            len(result),
            size=int(len(result) * 0.1),
            replace=False
        )
        result[random_indices] = np.random.randint(0, 256, size=len(random_indices))
    
    return result

def main():
    print("Step 1: Analyzing real ransomware samples...")
    
    # Get all real ransomware files
    real_files = []
    for root, dirs, files in os.walk(REAL_RANSOMWARE_FOLDER):
        for file in files:
            real_files.append(os.path.join(root, file))
    
    if len(real_files) == 0:
        print("ERROR: No real ransomware samples found!")
        print(f"Check folder: {REAL_RANSOMWARE_FOLDER}")
        return
    
    print(f"Found {len(real_files)} real ransomware samples")
    
    # Analyze patterns from real ransomware
    print("\nStep 2: Extracting ransomware characteristics...")
    patterns = []
    
    for filepath in tqdm(real_files):
        byte_data = read_file_bytes(filepath)
        if byte_data is not None:
            pattern = analyze_ransomware_pattern(byte_data)
            if pattern is not None:
                patterns.append(pattern)
    
    print(f"Extracted patterns from {len(patterns)} samples")
    
    if len(patterns) == 0:
        print("ERROR: Could not extract any patterns!")
        return
    
    # Calculate average characteristics
    avg_entropy = np.mean([p['entropy'] for p in patterns])
    avg_size = int(np.mean([p['length'] for p in patterns]))
    
    print(f"\nRansomware characteristics:")
    print(f"  Average entropy: {avg_entropy:.2f}")
    print(f"  Average size: {avg_size:,} bytes")
    
    # Generate synthetic samples
    print(f"\nStep 3: Generating {NUM_SAMPLES} synthetic ransomware samples...")
    print("(This mimics real ransomware patterns)\n")
    
    created = 0
    for i in tqdm(range(NUM_SAMPLES)):
        # Generate base synthetic sample
        synthetic_data = generate_synthetic_sample(patterns, avg_size)
        
        if synthetic_data is not None:
            # Apply ransomware-like transformations
            random_pattern = random.choice(patterns)
            transformed_data = apply_ransomware_transformations(synthetic_data, random_pattern)
            
            # Save
            output_path = os.path.join(OUTPUT_FOLDER, f"synthetic_ransomware_{i:04d}.bin")
            try:
                with open(output_path, 'wb') as f:
                    f.write(transformed_data.tobytes())
                created += 1
            except Exception as e:
                print(f"Error saving sample {i}: {e}")
    
    print(f"\n{'='*60}")
    print(f"✅ SUCCESS!")
    print(f"{'='*60}")
    print(f"Created: {created}/{NUM_SAMPLES} synthetic samples")
    print(f"Location: {OUTPUT_FOLDER}")
    print(f"\nThese samples mimic the patterns of your {len(real_files)} real ransomware samples")
    print(f"Dataset is now ready for training!")

if __name__ == "__main__":
    main()