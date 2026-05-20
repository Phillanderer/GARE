import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { Job } from '../types';

const JobsList = () => {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadJobs();
    const interval = setInterval(loadJobs, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const loadJobs = async () => {
    try {
      const response = await api.listJobs();
      setJobs(response.jobs);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load jobs');
    } finally {
      setLoading(false);
    }
  };

  const handleClearJobs = async () => {
    if (jobs.length === 0) return;

    const confirmed = window.confirm(
      `Are you sure you want to delete all ${jobs.length} job(s)?\n\nThis will permanently delete all job data, reports, and Ghidra projects.`
    );

    if (!confirmed) return;

    try {
      // Delete all jobs
      await Promise.all(jobs.map(job => api.deleteJob(job.id)));

      // Reload jobs list
      await loadJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear jobs');
    }
  };

  const handleDeleteJob = async (e: React.MouseEvent, jobId: string, filename: string) => {
    // Prevent navigation to job detail
    e.preventDefault();
    e.stopPropagation();

    const confirmed = window.confirm(
      `Are you sure you want to delete "${filename}"?\n\nThis will permanently delete all job data, reports, and Ghidra project.`
    );

    if (!confirmed) return;

    try {
      await api.deleteJob(jobId);
      await loadJobs();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete job');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#3fb950';
      case 'failed': return '#f85149';
      case 'running':
      case 'analyzing_ghidra':
      case 'agent_running':
      case 'report_writing': return '#58a6ff';
      case 'queued': return '#f0883e';
      case 'canceled': return '#8b949e';
      default: return '#8b949e';
    }
  };

  if (loading) {
    return <div style={styles.loading}>Loading jobs...</div>;
  }

  if (error) {
    return <div style={styles.error}>{error}</div>;
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h2 style={styles.heading}>Analysis Jobs</h2>
          <p style={styles.count}>{jobs.length} total</p>
        </div>
        {jobs.length > 0 && (
          <button onClick={handleClearJobs} style={styles.clearButton}>
            Clear All Jobs
          </button>
        )}
      </div>

      {jobs.length === 0 ? (
        <div style={styles.empty}>
          <p>No jobs yet. Upload a binary to get started.</p>
          <Link to="/" style={styles.link}>Upload Binary</Link>
        </div>
      ) : (
        <div style={styles.jobList}>
          {jobs.map((job) => (
            <div key={job.id} style={styles.jobCardWrapper}>
              <Link
                to={`/jobs/${job.id}`}
                style={styles.jobCard}
              >
                <div style={styles.jobHeader}>
                  <h3 style={styles.jobTitle}>{job.filename}</h3>
                  <span
                    style={{
                      ...styles.status,
                      background: getStatusColor(job.status),
                    }}
                  >
                    {job.status}
                  </span>
                </div>

                <div style={styles.jobDetails}>
                  <p style={styles.jobMeta}><strong>Job ID:</strong> {job.id}</p>
                  <p style={styles.jobMeta}><strong>SHA256:</strong> {job.sha256.slice(0, 16)}...</p>
                  <p style={styles.jobMeta}>
                    <strong>Created:</strong> {new Date(job.created_at).toLocaleString()}
                  </p>
                  <p style={styles.jobMeta}>
                    <strong>Method:</strong> {job.intensity || 'standard'}
                  </p>
                  {job.completed_at && (
                    <p style={styles.jobMeta}>
                      <strong>Runtime:</strong>{' '}
                      {(() => {
                        const seconds = Math.round(
                          (new Date(job.completed_at).getTime() - new Date(job.created_at).getTime()) / 1000
                        );
                        if (seconds < 60) return `${seconds}s`;
                        const mins = Math.floor(seconds / 60);
                        const secs = seconds % 60;
                        return `${mins}m ${secs}s`;
                      })()}
                    </p>
                  )}
                </div>

                <div style={styles.progressContainer}>
                  <div
                    style={{
                      ...styles.progressBar,
                      width: `${job.progress}%`,
                    }}
                  />
                </div>
                <p style={styles.progressText}>{job.progress}% complete</p>
              </Link>
              <button
                onClick={(e) => handleDeleteJob(e, job.id, job.filename)}
                style={styles.deleteButton}
                title="Delete job"
              >
                [X]
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '900px',
    margin: '0 auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '2rem',
  },
  heading: {
    color: '#c9d1d9',
  },
  count: {
    color: '#8b949e',
  },
  clearButton: {
    padding: '0.75rem 1.5rem',
    background: '#da3633',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '0.95rem',
    transition: 'background 0.2s',
  },
  loading: {
    textAlign: 'center',
    color: '#8b949e',
    padding: '3rem',
  },
  error: {
    padding: '1rem',
    background: '#f85149',
    color: '#ffffff',
    borderRadius: '6px',
  },
  empty: {
    textAlign: 'center',
    padding: '3rem',
    color: '#8b949e',
  },
  link: {
    display: 'inline-block',
    marginTop: '1rem',
    padding: '0.75rem 1.5rem',
    background: '#238636',
    color: '#ffffff',
    textDecoration: 'none',
    borderRadius: '6px',
  },
  jobList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  jobCardWrapper: {
    position: 'relative',
  },
  jobCard: {
    display: 'block',
    padding: '1.5rem',
    paddingRight: '3.5rem',
    background: '#161b22',
    borderRadius: '6px',
    border: '1px solid #30363d',
    textDecoration: 'none',
    transition: 'border-color 0.2s',
  },
  deleteButton: {
    position: 'absolute',
    top: '1rem',
    right: '1rem',
    width: '32px',
    height: '32px',
    background: '#da3633',
    color: '#ffffff',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '1.2rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'background 0.2s',
    lineHeight: '1',
    padding: '0',
  },
  jobHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
  },
  jobTitle: {
    color: '#c9d1d9',
    fontSize: '1.1rem',
  },
  status: {
    padding: '0.25rem 0.75rem',
    borderRadius: '12px',
    fontSize: '0.85rem',
    fontWeight: 'bold',
    color: '#ffffff',
  },
  jobDetails: {
    marginBottom: '1rem',
  },
  jobMeta: {
    color: '#8b949e',
    fontSize: '0.9rem',
    marginBottom: '0.25rem',
  },
  progressContainer: {
    width: '100%',
    height: '8px',
    background: '#21262d',
    borderRadius: '4px',
    overflow: 'hidden',
    marginBottom: '0.5rem',
  },
  progressBar: {
    height: '100%',
    background: '#238636',
    transition: 'width 0.3s',
  },
  progressText: {
    color: '#8b949e',
    fontSize: '0.85rem',
  },
};

export default JobsList;
