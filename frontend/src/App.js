import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem('theme');
    return saved ? saved === 'dark' : false;
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (selected) {
      setFile(selected);
      setResult(null);
      setError(null);
    }
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    const dropped = e.dataTransfer.files[0];
    if (dropped) {
      setFile(dropped);
      setResult(null);
      setError(null);
    }
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const scanFile = async () => {
    if (!file) return;

    setScanning(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('http://localhost:5000/api/scan', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Error scanning file. Make sure the backend server is running.');
    } finally {
      setScanning(false);
    }
  };

  const resetScan = () => {
    setFile(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="app">
      {/* Theme Toggle */}
      <button
        className="theme-toggle"
        onClick={() => setIsDark(!isDark)}
        title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      >
        {isDark ? '☀️' : '🌙'}
      </button>

      <main className="main">
        {/* Header */}
        <div className="header">
          <div className="logo">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="logo-icon">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <h1>RansomGuard</h1>
          </div>
          <p className="tagline">
            Analyse suspicious files to detect ransomware and other threats using AI-powered XGBoost ML engine.
          </p>
        </div>

        {/* Upload Area */}
        {!result && (
          <div className="upload-section">
            <div
              className={`drop-area ${file ? 'has-file' : ''}`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
            >
              <div className="drop-icon">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                  <polyline points="17 8 12 3 7 8" />
                  <line x1="12" y1="3" x2="12" y2="15" />
                </svg>
              </div>

              {file ? (
                <div className="file-selected">
                  <span className="file-name">{file.name}</span>
                  <span className="file-size">{(file.size / 1024 / 1024).toFixed(2)} MB</span>
                </div>
              ) : (
                <p className="drop-text">Drag & drop a file here</p>
              )}

              <label className="choose-btn">
                <input
                  type="file"
                  onChange={handleFileChange}
                  style={{ display: 'none' }}
                />
                {file ? 'Change file' : 'Choose file'}
              </label>
            </div>

            <button
              className="scan-btn"
              onClick={scanFile}
              disabled={!file || scanning}
            >
              {scanning ? (
                <>
                  <span className="spinner"></span>
                  Scanning...
                </>
              ) : (
                'Scan File'
              )}
            </button>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="error-msg">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="15" y1="9" x2="9" y2="15" />
              <line x1="9" y1="9" x2="15" y2="15" />
            </svg>
            {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="results">
            <div className={`verdict ${result.is_ransomware ? 'danger' : 'safe'}`}>
              <div className="verdict-icon">
                {result.is_ransomware ? (
                  <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                ) : (
                  <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                    <polyline points="22 4 12 14.01 9 11.01" />
                  </svg>
                )}
              </div>
              <h2>{result.prediction}</h2>
              <span className="confidence">Confidence: {result.confidence.toFixed(1)}%</span>
            </div>

            <div className="details">
              <div className="detail-row">
                <span className="label">File</span>
                <span className="value">{result.filename}</span>
              </div>
              <div className="detail-row">
                <span className="label">Ransomware</span>
                <div className="bar-wrap">
                  <div className="bar danger-bar" style={{ width: `${result.ransomware_probability}%` }}></div>
                </div>
                <span className="value">{result.ransomware_probability.toFixed(1)}%</span>
              </div>
              <div className="detail-row">
                <span className="label">Benign</span>
                <div className="bar-wrap">
                  <div className="bar safe-bar" style={{ width: `${result.benign_probability}%` }}></div>
                </div>
                <span className="value">{result.benign_probability.toFixed(1)}%</span>
              </div>
              <div className="detail-row">
                <span className="label">Entropy</span>
                <span className="value">{result.entropy.toFixed(4)}</span>
              </div>
              <div className="detail-row">
                <span className="label">File Size</span>
                <span className="value">{(result.file_size / 1024).toFixed(2)} KB</span>
              </div>
            </div>

            <button className="scan-again-btn" onClick={resetScan}>
              ← Scan another file
            </button>
          </div>
        )}

        {/* Footer */}
        <footer className="footer">
          <p>Powered by XGBoost ML · Model Accuracy: 99.11%</p>
        </footer>
      </main>
    </div>
  );
}

export default App;