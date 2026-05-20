import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

type Intensity = 'quick' | 'standard' | 'deep';

const intensityOptions: { value: Intensity; label: string; desc: string }[] = [
  { value: 'quick', label: 'Quick', desc: 'High-level overview, key functions only' },
  { value: 'standard', label: 'Standard', desc: 'Thorough analysis of significant functions' },
  { value: 'deep', label: 'Deep', desc: 'Exhaustive analysis of all functions' },
];

const UploadView = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [intensity, setIntensity] = useState<Intensity>('standard');
  const navigate = useNavigate();

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
      setError(null);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleRemove = () => {
    setFile(null);
    setError(null);
  };

  const handleUpload = async () => {
    if (!file) return;

    // Show confirmation dialog
    const confirmed = window.confirm(
      `Are you sure you want to analyze "${file.name}"?\n\nThis will start an automated reverse engineering analysis using Ghidra and AI.`
    );

    if (!confirmed) return;

    setUploading(true);
    setError(null);

    try {
      const response = await api.uploadBinary(file, intensity);
      navigate(`/jobs/${response.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.heading}>Upload Binary for Analysis</h2>

      <div
        style={styles.dropZone}
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
      >
        <p style={styles.dropText}>Drag and drop a binary here</p>
        <p style={styles.orText}>or</p>
        <label style={styles.fileLabel}>
          Choose File
          <input
            type="file"
            onChange={handleFileSelect}
            style={styles.fileInput}
          />
        </label>
      </div>

      <div style={styles.intensitySection}>
        <p style={styles.intensityLabel}>Analysis Intensity</p>
        <div style={styles.intensityGroup}>
          {intensityOptions.map((opt) => (
            <button
              key={opt.value}
              onClick={() => setIntensity(opt.value)}
              style={
                intensity === opt.value
                  ? { ...styles.intensityBtn, ...styles.intensityBtnActive }
                  : styles.intensityBtn
              }
            >
              <span style={styles.intensityBtnLabel}>{opt.label}</span>
              <span style={styles.intensityBtnDesc}>{opt.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {file && (
        <div style={styles.fileInfo}>
          <p style={styles.fileName}>Selected: {file.name}</p>
          <p style={styles.fileSize}>Size: {(file.size / 1024 / 1024).toFixed(2)} MB</p>
          <div style={styles.buttonGroup}>
            <button
              onClick={handleUpload}
              disabled={uploading}
              style={uploading ? { ...styles.button, ...styles.buttonDisabled } : styles.button}
            >
              {uploading ? 'Uploading...' : 'Start Analysis'}
            </button>
            <button
              onClick={handleRemove}
              disabled={uploading}
              style={uploading ? { ...styles.removeButton, ...styles.buttonDisabled } : styles.removeButton}
            >
              Remove
            </button>
          </div>
        </div>
      )}

      {error && <div style={styles.error}>{error}</div>}
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '600px',
    margin: '0 auto',
  },
  heading: {
    color: '#c9d1d9',
    marginBottom: '2rem',
    textAlign: 'center',
  },
  dropZone: {
    border: '2px dashed #30363d',
    borderRadius: '8px',
    padding: '3rem',
    textAlign: 'center',
    cursor: 'pointer',
    transition: 'border-color 0.2s',
  },
  dropText: {
    color: '#8b949e',
    marginBottom: '1rem',
  },
  orText: {
    color: '#8b949e',
    margin: '1rem 0',
  },
  fileLabel: {
    display: 'inline-block',
    padding: '0.75rem 1.5rem',
    background: '#21262d',
    color: '#c9d1d9',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background 0.2s',
  },
  fileInput: {
    display: 'none',
  },
  fileInfo: {
    marginTop: '2rem',
    padding: '1rem',
    background: '#161b22',
    borderRadius: '6px',
  },
  fileName: {
    color: '#c9d1d9',
    marginBottom: '0.5rem',
  },
  fileSize: {
    color: '#8b949e',
    marginBottom: '1rem',
  },
  buttonGroup: {
    display: 'flex',
    gap: '1rem',
  },
  button: {
    padding: '0.75rem 1.5rem',
    background: '#238636',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '1rem',
    transition: 'background 0.2s',
  },
  removeButton: {
    padding: '0.75rem 1.5rem',
    background: '#da3633',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '1rem',
    transition: 'background 0.2s',
  },
  buttonDisabled: {
    background: '#30363d',
    cursor: 'not-allowed',
  },
  intensitySection: {
    marginTop: '2rem',
  },
  intensityLabel: {
    color: '#c9d1d9',
    marginBottom: '0.75rem',
    fontWeight: 500,
    textAlign: 'center',
  },
  intensityGroup: {
    display: 'flex',
    gap: '0.75rem',
  },
  intensityBtn: {
    flex: 1,
    padding: '0.75rem',
    background: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '6px',
    cursor: 'pointer',
    textAlign: 'left' as const,
    transition: 'border-color 0.2s',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.25rem',
  },
  intensityBtnActive: {
    borderColor: '#238636',
    background: '#0d1117',
  },
  intensityBtnLabel: {
    color: '#c9d1d9',
    fontWeight: 600,
    fontSize: '0.95rem',
  },
  intensityBtnDesc: {
    color: '#8b949e',
    fontSize: '0.8rem',
  },
  error: {
    marginTop: '1rem',
    padding: '1rem',
    background: '#f85149',
    color: '#ffffff',
    borderRadius: '6px',
  },
};

export default UploadView;
