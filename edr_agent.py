import os
import time
import json
import requests
import pickle
import numpy as np
import math
from collections import Counter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import shutil

# Configuration
MONITORED_DIR = "Security_Monitored_Zone"
LOGS_DIR = "logs"
EDR_LOG_FILE = os.path.join(LOGS_DIR, "edr_events.log")
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3" # You can change this to mistral or phi3 depending on what you downloaded
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'Model', 'ransomware_detector_xgboost.pkl')

os.makedirs(MONITORED_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

def log_event(message):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    formatted_msg = f"{timestamp} {message}"
    print(formatted_msg)
    with open(EDR_LOG_FILE, "a") as f:
        f.write(formatted_msg + "\n")

# Load XGBoost Model
print("[*] Loading XGBoost AI Model...")
with open(MODEL_PATH, 'rb') as f:
    xgb_model = pickle.load(f)

# Utility Functions from app.py
def calculate_entropy(data):
    if not data: return 0
    counter = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in counter.values())

def extract_features(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(100000)
        if len(data) == 0: return None
        
        byte_hist = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        byte_hist = byte_hist / len(data)
        entropy = calculate_entropy(data)
        file_size = len(data)
        printable = sum(1 for b in data if 32 <= b <= 126)
        printable_ratio = printable / len(data)
        
        features = np.concatenate([byte_hist, [entropy, file_size, printable_ratio]])
        return features.reshape(1, -1)
    except Exception as e:
        log_event(f"[-] Feature extraction failed for {filepath}: {e}")
        return None

def generate_incident_report(threat_data):
    """Uses Ollama to generate a forensic report after an attack is blocked."""
    prompt = f"Write a professional, clinical cybersecurity incident report for the following event. Make it 3-4 sentences maximum. Data: {threat_data}"
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=10)
        if response.status_code == 200:
            return response.json().get('response', 'Error reading response.')
    except:
        return "[OLLAMA OFFLINE] Could not connect to Ollama to generate forensic report."

def analyze_script_with_ollama(filepath):
    """Sends a script's contents to Ollama to detect malicious behavior."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read(2000) # Read first 2000 chars
        
        prompt = f"You are an expert cybersecurity AI. Analyze this script and determine if it is malicious/ransomware. Reply with exactly 'MALICIOUS' or 'SAFE'. Script:\n\n{code}"
        payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
        
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=20)
        if response.status_code == 200:
            resultText = response.json().get('response', '').strip().upper()
            return 'MALICIOUS' in resultText
    except Exception as e:
        log_event(f"[-] Ollama Error: {e}")
    return False

def quarantine_file(filepath):
    """Renames malicious file to quarantine it and prevent execution."""
    try:
        new_path = filepath + ".quarantined"
        os.rename(filepath, new_path)
        return new_path
    except Exception as e:
        log_event(f"[-] Failed to quarantine: {e}")
        return None

def trigger_process_kill(suspect_file_path):
    """Simulates finding and terminating a process that touched the canary file."""
    log_event(f"[!!!] TRAP TRIPPED! Malicious modification to {suspect_file_path}")
    log_event("[!!!] Executing Process Termination Protocol...")
    # In a real C++ driver, this terminates instantly. In Python, we have to guess or scan.
    # For this VM demo, we will log the simulated kill. 
    # (Do not blindly kill explorer.exe or system processes if they just touch it).
    log_event("[+] Successfully forcefully terminated ransomware process (Simulation Event).")

LAST_TRIP_TIME = 0

class RansomwareAgentHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory: return
        
        # Windows needs a moment to finish writing the file before we can read it safely
        time.sleep(1.5)
        filepath = event.src_path
        filename = os.path.basename(filepath)
        
        # Ignores
        if "trap_canary" in filename or filename.endswith('.quarantined'):
            return

        log_event(f"[*] New file detected: {filename}")
        
        # 1. XGBoost Pipeline for Executables (and extension-less Payloads)
        if not filename.endswith(('.bat', '.ps1', '.py', '.vbs', '.quarantined', '.txt', '.log')):
            features = extract_features(filepath)
            if features is not None:
                prediction = xgb_model.predict(features)[0]
                prob = xgb_model.predict_proba(features)[0]
                
                if prediction == 1: # Ransomware
                    log_event(f"[!] XDR ALERT: XGBoost detected '{filename}' as Ransomware ({prob[1]*100:.2f}%)")
                    q_path = quarantine_file(filepath)
                    report = generate_incident_report(f"File {filename} detected as ransomware by XGBoost with {(prob[1]*100):.2f}% probability and was quarantined.")
                    log_event(f"[+] Forensic Report: {report}")
                else:
                    log_event(f"[+] XGBoost cleared '{filename}'. File is safe.")
        
        # 2. Ollama Pipeline for Scripts
        elif filename.endswith(('.bat', '.ps1', '.py', '.vbs')):
            log_event(f"[*] Sending script '{filename}' to Ollama for behavioral analysis...")
            is_bad = analyze_script_with_ollama(filepath)
            if is_bad:
                log_event(f"[!] XDR ALERT: Ollama flagged script '{filename}' as Malicious.")
                q_path = quarantine_file(filepath)
                report = generate_incident_report(f"Script file {filename} identified as containing malicious instructions by Ollama LLM and was quarantined.")
                log_event(f"[+] Forensic Report: {report}")
            else:
                log_event(f"[+] Ollama cleared '{filename}'. Script is safe.")

    def on_modified(self, event):
        global LAST_TRIP_TIME
        if event.is_directory: return
        filepath = event.src_path
        
        # 3. Canary Trap Failsafe (with debounce to prevent infinite loop)
        if "trap_canary" in os.path.basename(filepath) and not filepath.endswith('.quarantined'):
            current_time = time.time()
            if current_time - LAST_TRIP_TIME > 5: # 5 second cooldown
                LAST_TRIP_TIME = current_time
                trigger_process_kill(filepath)
                
                # Recreate trap safely
                time.sleep(1) # Let the text editor release its lock first
                create_canary()

def create_canary():
    trap_path = os.path.join(MONITORED_DIR, "trap_canary_passwords.txt")
    try:
        with open(trap_path, 'w') as f:
            f.write("Do not modify this file. It is a honeypot for ransomware detection.")
    except Exception as e:
        log_event(f"[-] Could not recreate canary immediately: {e}")
    # In Windows you can use os.system(f"attrib +h {trap_path}") to hide it, but we'll leave it visible for testing.

if __name__ == "__main__":
    print("========================================")
    print("   RansomGuard EDR Agent - Active       ")
    print("========================================")
    
    # Plant the trap
    create_canary()
    print(f"[*] Honeypot Canary planted in '{MONITORED_DIR}'")
    print(f"[*] Watchdog actively monitoring '{MONITORED_DIR}'...")
    
    event_handler = RansomwareAgentHandler()
    observer = Observer()
    observer.schedule(event_handler, path=MONITORED_DIR, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
