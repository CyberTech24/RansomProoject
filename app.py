from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import numpy as np
import pickle
import math
from collections import Counter
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max  ← CHANGED

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

MODEL_PATH = r"C:\Users\THE GHOST\Downloads\RansomwareProject\RansomwareProject\Model\ransomware_detector_xgboost.pkl"
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

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
            data = f.read(100000)
        
        if len(data) == 0:
            return None
        
        byte_hist = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        byte_hist = byte_hist / len(data)
        
        entropy = calculate_entropy(data)
        file_size = len(data)
        printable = sum(1 for b in data if 32 <= b <= 126)
        printable_ratio = printable / len(data)
        
        features = np.concatenate([byte_hist, [entropy, file_size, printable_ratio]])
        return features.reshape(1, -1)
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        features = extract_features(filepath)
        
        if features is None:
            os.remove(filepath)
            return jsonify({'error': 'Could not analyze file'}), 400
        
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        
        with open(filepath, 'rb') as f:
            data = f.read(100000)
        entropy = calculate_entropy(data)
        file_size = os.path.getsize(filepath)
        
        os.remove(filepath)
        
        result = {
            'filename': filename,
            'prediction': 'RANSOMWARE DETECTED' if prediction == 1 else 'FILE IS SAFE',
            'is_ransomware': bool(prediction == 1),
            'confidence': float(probability[prediction] * 100),
            'ransomware_probability': float(probability[1] * 100),
            'benign_probability': float(probability[0] * 100),
            'entropy': float(entropy),
            'file_size': file_size
        }
        
        return jsonify(result)
    
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)