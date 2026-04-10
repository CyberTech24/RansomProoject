import os
import time
import json
import requests
import pickle
import numpy as np
import math
import hashlib
from collections import Counter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import shutil
import pyfiglet
from colorama import init, Fore, Back, Style

# Initialize Colorama for Windows
init(autoreset=True)

try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False

# Configuration
MONITORED_DIR = "Security_Monitored_Zone"
LOGS_DIR = "logs"
EDR_LOG_FILE = os.path.join(LOGS_DIR, "edr_events.log")
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3" # You can change this to mistral or phi3 depending on what you downloaded

# Secure Cryptographic Whitelist
KNOWN_GOOD_HASHES = [
    '194362cf24cd0db4b573096108460a34c7f80a20c5f2aa60d06ef817be9f73a1', # Git Installer
    '0a9530b8227313436447d90fc55c2cf033d48e1f6c2a4d87d907068689392c03', # Ollama Installer
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'Model', 'ransomware_detector_xgboost.pkl')

os.makedirs(MONITORED_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
IS_SELF_MODIFYING = False
REPORTS_DIR = "forensic_reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def log_event(message, is_banner=False, is_safe=False):
    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
    
    # Highlighting Logic
    color = ""
    if "[!]" in message: color = Fore.RED + Style.BRIGHT
    elif "[!!!]" in message: color = Back.RED + Fore.WHITE + Style.BRIGHT
    elif "[+]" in message: color = Fore.GREEN + Style.BRIGHT
    elif "[*]" in message: color = Fore.CYAN
    
    if is_banner:
        banner_text = "THREAT DETECTED" if not is_safe else "FILE SECURE"
        banner_color = Fore.RED if not is_safe else Fore.GREEN
        banner = pyfiglet.figlet_format(banner_text, font="small")
        print("\n" + banner_color + Style.BRIGHT + "=" * 60)
        print(banner_color + Style.BRIGHT + banner)
        print(banner_color + Style.BRIGHT + " " + message)
        print(banner_color + Style.BRIGHT + "=" * 60 + "\n")
    else:
        formatted_msg = f"{timestamp} {message}"
        print(color + formatted_msg)
    
    with open(EDR_LOG_FILE, "a") as f:
        f.write(f"{timestamp} {message}\n")

# Load XGBoost Model
print("[*] Loading XGBoost AI Model...")
with open(MODEL_PATH, 'rb') as f:
    xgb_model = pickle.load(f)

# Utility Functions from app.py
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().lower()
    except Exception as e:
        return ""

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
        base_new_path = filepath + ".quarantined"
        new_path = base_new_path
        counter = 1
        while os.path.exists(new_path):
            new_path = f"{base_new_path}.{counter}"
            counter += 1
            
        os.rename(filepath, new_path)
        return new_path
    except Exception as e:
        log_event(f"[-] Failed to quarantine: {e}")
        return None

def trigger_process_kill(suspect_file_path):
    """Scans for and terminates suspicious processes that recently accessed the canary file."""
    log_event(f"[!!!] TRAP TRIPPED! Malicious modification to {suspect_file_path}")
    log_event("[!!!] Executing Process Termination Protocol...")
    
    killed_processes = []
    # Safe system processes that should NEVER be killed
    SAFE_PROCESSES = {'explorer.exe', 'svchost.exe', 'csrss.exe', 'wininit.exe', 
                      'winlogon.exe', 'services.exe', 'lsass.exe', 'System', 
                      'smss.exe', 'dwm.exe', 'taskhostw.exe', 'python.exe',
                      'pythonw.exe', 'cmd.exe', 'powershell.exe', 'conhost.exe',
                      'code.exe', 'msedge.exe', 'chrome.exe', 'notepad.exe'}
    
    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        try:
            proc_name = proc.info['name']
            proc_pid = proc.info['pid']
            # Skip safe system processes
            if proc_name.lower() in {s.lower() for s in SAFE_PROCESSES}:
                continue
            # Check if the process has open file handles on the monitored directory
            try:
                open_files = proc.open_files()
                for f in open_files:
                    if MONITORED_DIR in f.path:
                        log_event(f"[!!!] SUSPECT PROCESS IDENTIFIED: {proc_name} (PID: {proc_pid}) has handle on monitored zone.")
                        proc.kill()
                        killed_processes.append({'name': proc_name, 'pid': proc_pid, 'status': 'TERMINATED'})
                        log_event(f"[+] Successfully KILLED process {proc_name} (PID: {proc_pid})")
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    if not killed_processes:
        log_event("[*] No active suspicious processes found with handles on the monitored zone.")
        killed_processes.append({'name': 'N/A', 'pid': 'N/A', 'status': 'No suspect process found (simulated kill)'})
    
    return killed_processes

def extract_network_origin(filepath):
    """Reads the Windows 'Mark of the Web' NTFS data stream to find the download origin."""
    try:
        zone_file = filepath + ":Zone.Identifier"
        zone_data = {}
        with open(zone_file, "r", encoding="utf-8") as f:
            for line in f.readlines():
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    zone_data[key] = value
        return zone_data
    except Exception:
        return None

def extract_pe_headers(filepath):
    """Extracts PE (Portable Executable) header information from .exe files."""
    if not PE_AVAILABLE:
        return {'error': 'pefile library not installed'}
    
    try:
        pe = pefile.PE(filepath)
        
        # Extract imported DLLs
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                funcs = [imp.name.decode('utf-8', errors='ignore') for imp in entry.imports if imp.name]
                imports.append({'dll': dll_name, 'functions': funcs[:10]})  # Limit to 10 functions per DLL
        
        # Extract sections
        sections = []
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sections.append({
                'name': sec_name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(section.get_entropy(), 4)
            })
        
        # Compile timestamp
        compile_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp))
        
        # Suspicious indicators
        suspicious_dlls = []
        DANGER_DLLS = ['crypt32.dll', 'advapi32.dll', 'ws2_32.dll', 'wininet.dll', 'urlmon.dll']
        for imp in imports:
            if imp['dll'].lower() in DANGER_DLLS:
                suspicious_dlls.append(imp['dll'])
        
        pe_data = {
            'machine': hex(pe.FILE_HEADER.Machine),
            'compile_time': compile_time,
            'num_sections': pe.FILE_HEADER.NumberOfSections,
            'sections': sections,
            'imports': imports,
            'suspicious_dlls': suspicious_dlls,
            'is_dll': pe.is_dll(),
            'is_exe': pe.is_exe()
        }
        pe.close()
        return pe_data
    except Exception as e:
        return {'error': str(e)}

def capture_process_memory(pid=None):
    """Captures memory statistics of suspicious processes running on the system."""
    memory_snapshot = []
    try:
        # Get system-wide memory info
        mem = psutil.virtual_memory()
        system_mem = {
            'total_gb': round(mem.total / (1024**3), 2),
            'used_gb': round(mem.used / (1024**3), 2),
            'percent': mem.percent
        }
        
        # Get top 10 memory-consuming processes
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'memory_percent']):
            try:
                procs.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'rss_mb': round(proc.info['memory_info'].rss / (1024**2), 2),
                    'percent': round(proc.info['memory_percent'], 2)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by memory usage
        procs.sort(key=lambda x: x['rss_mb'], reverse=True)
        memory_snapshot = procs[:10]
        
        return {'system': system_mem, 'top_processes': memory_snapshot}
    except Exception as e:
        return {'error': str(e)}

# ══════════════════════════════════════════════════════════════════
#  ADVANCED NETWORK FORENSICS MODULE
# ══════════════════════════════════════════════════════════════════

def run_nids_trace():
    """Network Intrusion Detection System - Scans active network connections and geolocates external IPs."""
    log_event("[*] NIDS: Initiating Network Intrusion Trace...")
    traced_connections = []
    try:
        connections = psutil.net_connections(kind='inet')
        external_ips = set()
        
        for conn in connections:
            if conn.raddr:  # Remote address exists (active connection)
                ip = conn.raddr.ip
                port = conn.raddr.port
                # Filter out local/private IPs
                if not ip.startswith(('127.', '0.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '::1', 'fe80')):
                    external_ips.add((ip, port, conn.status, conn.pid))
        
        if not external_ips:
            log_event("[+] NIDS: No suspicious external connections detected.")
            return traced_connections
        
        log_event(f"[!] NIDS: Detected {len(external_ips)} active external connection(s). Tracing origins...")
        
        for ip, port, status, pid in external_ips:
            # Get process name from PID
            proc_name = "Unknown"
            try:
                if pid:
                    proc_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Geolocate the IP
            country = "Unknown"
            city = "Unknown"
            org = "Unknown"
            try:
                geo_response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,org", timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('status') == 'success':
                        country = geo_data.get('country', 'Unknown')
                        city = geo_data.get('city', 'Unknown')
                        org = geo_data.get('org', 'Unknown')
            except Exception:
                pass
            
            trace_entry = {
                'ip': ip, 'port': port, 'status': status,
                'process': proc_name, 'pid': pid,
                'city': city, 'country': country, 'isp': org
            }
            traced_connections.append(trace_entry)
            log_event(f"[!] NIDS TRACE: {ip}:{port} | Status: {status} | Process: {proc_name} (PID: {pid}) | Location: {city}, {country} | ISP: {org}")
        
        log_event("[+] NIDS: Network trace complete.")
    except Exception as e:
        log_event(f"[-] NIDS: Network scan failed: {e}")
    return traced_connections

def save_forensic_report(filename, file_hash, confidence, nids_data, filepath_for_analysis=None):
    """Saves a complete forensic incident report to disk."""
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = filename.replace('\\', '_').replace('/', '_').replace(':', '')
    report_filename = f"INCIDENT_{timestamp}_{safe_name}.txt"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    # Collect all forensic data
    origin_data = None
    pe_data = None
    mem_data = None
    
    if filepath_for_analysis:
        log_event("[*] Collecting forensic data: Mark of the Web...")
        origin_data = extract_network_origin(filepath_for_analysis)
        
        if filepath_for_analysis.lower().endswith(('.exe', '.dll', '.sys')):
            log_event("[*] Collecting forensic data: PE Header Analysis...")
            pe_data = extract_pe_headers(filepath_for_analysis)
    
    log_event("[*] Collecting forensic data: Memory Snapshot...")
    mem_data = capture_process_memory()
    
    try:
        with open(report_path, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("       RANSOMGUARD EDR - FORENSIC INCIDENT REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Report Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Incident ID      : INC-{timestamp.replace('-','').replace('_','')}\n\n")
            
            # --- THREAT SUMMARY ---
            f.write("-" * 70 + "\n")
            f.write("  THREAT SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"  File Name      : {filename}\n")
            f.write(f"  SHA-256 Hash   : {file_hash}\n")
            f.write(f"  AI Confidence  : {confidence:.2f}%\n")
            f.write(f"  Verdict        : RANSOMWARE / INTRUSION DETECTED\n")
            f.write(f"  Action Taken   : File Quarantined\n\n")
            
            # --- FILE ORIGIN (Mark of the Web) ---
            f.write("-" * 70 + "\n")
            f.write("  FILE ORIGIN (MARK OF THE WEB)\n")
            f.write("-" * 70 + "\n")
            if origin_data:
                for key, value in origin_data.items():
                    f.write(f"  {key:16s} : {value}\n")
            else:
                f.write("  No download origin detected (file may have been locally copied).\n")
            f.write("\n")
            
            # --- PE HEADER ANALYSIS ---
            f.write("-" * 70 + "\n")
            f.write("  PE HEADER ANALYSIS\n")
            f.write("-" * 70 + "\n")
            if pe_data and 'error' not in pe_data:
                f.write(f"  Machine Type   : {pe_data['machine']}\n")
                f.write(f"  Compile Time   : {pe_data['compile_time']}\n")
                f.write(f"  Is EXE         : {pe_data['is_exe']}\n")
                f.write(f"  Is DLL         : {pe_data['is_dll']}\n")
                f.write(f"  Sections       : {pe_data['num_sections']}\n\n")
                
                f.write("  PE Sections:\n")
                for sec in pe_data['sections']:
                    f.write(f"    [{sec['name']:8s}] Virtual: {sec['virtual_size']:>8} | Raw: {sec['raw_size']:>8} | Entropy: {sec['entropy']}\n")
                f.write("\n")
                
                if pe_data['suspicious_dlls']:
                    f.write("  [!] SUSPICIOUS DLL IMPORTS DETECTED:\n")
                    for dll in pe_data['suspicious_dlls']:
                        f.write(f"    - {dll}\n")
                    f.write("\n")
                
                f.write("  Imported DLLs:\n")
                for imp in pe_data['imports'][:15]:  # Limit output
                    f.write(f"    {imp['dll']}\n")
                    for func in imp['functions'][:5]:
                        f.write(f"      -> {func}\n")
                f.write("\n")
            elif pe_data and 'error' in pe_data:
                f.write(f"  PE Analysis failed: {pe_data['error']}\n\n")
            else:
                f.write("  File is not a PE executable. PE analysis skipped.\n\n")
            
            # --- NETWORK INTRUSION DETECTION ---
            f.write("-" * 70 + "\n")
            f.write("  NETWORK INTRUSION DETECTION (NIDS) RESULTS\n")
            f.write("-" * 70 + "\n")
            if nids_data:
                f.write(f"  Total External Connections : {len(nids_data)}\n\n")
                for i, conn in enumerate(nids_data, 1):
                    f.write(f"  Connection #{i}:\n")
                    f.write(f"    Remote IP    : {conn['ip']}:{conn['port']}\n")
                    f.write(f"    Status       : {conn['status']}\n")
                    f.write(f"    Process      : {conn['process']} (PID: {conn['pid']})\n")
                    f.write(f"    Location     : {conn['city']}, {conn['country']}\n")
                    f.write(f"    ISP / Org    : {conn['isp']}\n\n")
            else:
                f.write("  No suspicious external connections detected.\n\n")
            
            # --- MEMORY DUMP SNAPSHOT ---
            f.write("-" * 70 + "\n")
            f.write("  MEMORY DUMP SNAPSHOT\n")
            f.write("-" * 70 + "\n")
            if mem_data and 'error' not in mem_data:
                sys_mem = mem_data['system']
                f.write(f"  System RAM     : {sys_mem['used_gb']} GB / {sys_mem['total_gb']} GB ({sys_mem['percent']}% used)\n\n")
                f.write("  Top 10 Memory-Consuming Processes:\n")
                f.write(f"  {'PID':>7}  {'Process':25s}  {'RSS (MB)':>10}  {'Memory %':>8}\n")
                f.write("  " + "-" * 55 + "\n")
                for proc in mem_data['top_processes']:
                    f.write(f"  {proc['pid']:>7}  {proc['name']:25s}  {proc['rss_mb']:>10.2f}  {proc['percent']:>7.2f}%\n")
            else:
                f.write("  Memory snapshot unavailable.\n")
            f.write("\n")
            
            f.write("=" * 70 + "\n")
            f.write("  END OF REPORT\n")
            f.write("=" * 70 + "\n")
        
        log_event(f"[+] Forensic Report saved to: {report_path}")
        return report_path
    except Exception as e:
        log_event(f"[-] Failed to save forensic report: {e}")
        return None

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

        # Clean filename for logging in case malware drops a file with a newline in its name
        clean_name = filename.replace('\n', '').replace('\r', '')
        log_event(f"[*] New file detected: {clean_name}")
        
        # 0. Cryptographic Whitelist Check
        file_hash = calculate_sha256(filepath)
        if file_hash in KNOWN_GOOD_HASHES:
            msg = f"Cleared by Cryptographic Whitelist: '{clean_name}'. File is a mathematically verified trusted installer."
            log_event(msg, is_banner=True, is_safe=True)
            return
        
        # 1. XGBoost Pipeline for Executables (and extension-less Payloads)
        if not filename.endswith(('.bat', '.ps1', '.py', '.vbs', '.quarantined', '.txt', '.log')):
            features = extract_features(filepath)
            if features is not None:
                prediction = xgb_model.predict(features)[0]
                prob = xgb_model.predict_proba(features)[0]
                
                if prediction == 1: # Ransomware
                    alert_msg = f"XDR ALERT: XGBoost detected '{filename}' as Ransomware ({prob[1]*100:.2f}%)"
                    log_event(alert_msg, is_banner=(prob[1] > 0.8)) # Multi-line banner for high confidence
                    q_path = quarantine_file(filepath)
                    nids_data = run_nids_trace()
                    # Pass quarantined path for PE analysis, original path for MotW
                    analysis_path = q_path if q_path else filepath
                    save_forensic_report(filename, file_hash, prob[1]*100, nids_data, analysis_path)
                else:
                    log_event(f"XGBoost cleared '{filename}'. File is safe.", is_banner=True, is_safe=True)
        
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
        global LAST_TRIP_TIME, IS_SELF_MODIFYING
        if event.is_directory: return
        if IS_SELF_MODIFYING: return # Ignore our own edits
        
        filepath = event.src_path
        
        # 3. Canary Trap Failsafe (with debounce)
        if "trap_canary" in os.path.basename(filepath) and not filepath.endswith('.quarantined'):
            current_time = time.time()
            if current_time - LAST_TRIP_TIME > 5:
                LAST_TRIP_TIME = current_time
                trigger_process_kill(filepath)
                run_nids_trace()
                
                # Recreate trap safely
                time.sleep(1) # Let the text editor release its lock first
                create_canary()

def create_canary():
    global IS_SELF_MODIFYING
    trap_path = os.path.join(MONITORED_DIR, "trap_canary_passwords.txt")
    try:
        IS_SELF_MODIFYING = True
        with open(trap_path, 'w') as f:
            f.write("Do not modify this file. It is a honeypot for ransomware detection.")
        time.sleep(0.5) # Wait for filesystem to settle
        IS_SELF_MODIFYING = False
    except Exception as e:
        log_event(f"[-] Could not recreate canary immediately: {e}")
        IS_SELF_MODIFYING = False

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
