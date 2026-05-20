import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Job } from '../types';
import ReportViewer from './ReportViewer';

const JobDetail = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [job, setJob] = useState<Job | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'logs' | 'report'>('logs');
  const [userScrolledUp, setUserScrolledUp] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!jobId) return;

    loadJob();
    const interval = setInterval(loadJob, 3000); // Refresh every 3s
    return () => clearInterval(interval);
  }, [jobId]);

  // Detect if user manually scrolled up
  const handleScroll = () => {
    if (!logsContainerRef.current) return;

    const container = logsContainerRef.current;
    const isScrolledToBottom =
      container.scrollHeight - container.scrollTop <= container.clientHeight + 50; // 50px threshold

    setUserScrolledUp(!isScrolledToBottom);
  };

  // Auto-scroll logs to bottom ONLY if:
  // 1. Analysis is actively running
  // 2. User hasn't manually scrolled up
  // 3. Logs tab is active
  useEffect(() => {
    if (!job || !logsEndRef.current || activeTab !== 'logs') return;

    const isRunning =
      job.status === 'running' ||
      job.status === 'queued' ||
      job.status === 'analyzing_ghidra' ||
      job.status === 'agent_running' ||
      job.status === 'report_writing';

    // Only auto-scroll if job is running AND user hasn't scrolled up
    if (isRunning && !userScrolledUp) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, activeTab, job?.status, userScrolledUp]);

  const loadJob = async () => {
    if (!jobId) return;

    try {
      const jobData = await api.getJob(jobId);
      setJob(jobData);

      const logsData = await api.getJobLogs(jobId);
      setLogs(logsData);

      if (jobData.status === 'completed') {
        try {
          const reportData = await api.getReport(jobId);
          setReport(reportData);
        } catch (err) {
          console.error('Report not available yet:', err);
        }
      }

      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load job');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = () => {
    if (jobId) {
      api.downloadReport(jobId);
    }
  };

  const handleDownloadGhidraProject = () => {
    if (jobId) {
      api.downloadGhidraProject(jobId);
    }
  };

  const handleDownloadAnnotations = () => {
    if (jobId) {
      api.downloadAnnotations(jobId);
    }
  };

  const handleCancel = async () => {
    if (!jobId || !confirm('Are you sure you want to cancel this analysis?')) return;

    try {
      await api.cancelJob(jobId);
      await loadJob();
    } catch (err) {
      alert('Failed to cancel analysis: ' + (err instanceof Error ? err.message : 'Unknown error'));
    }
  };

  if (loading) {
    return <div style={styles.loading}>Loading job details...</div>;
  }

  if (error || !job) {
    return (
      <div style={styles.error}>
        {error || 'Job not found'}
        <button onClick={() => navigate('/jobs')} style={styles.button}>
          Back to Jobs
        </button>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h2 style={styles.title}>{job.filename}</h2>
          <p style={styles.subtitle}>Job ID: {job.id}</p>
        </div>
        <button onClick={() => navigate('/jobs')} style={styles.backButton}>
          Back to Jobs
        </button>
      </div>

      <div style={styles.statusAndActions}>
        <div style={styles.statusCard}>
          <div style={styles.statusRow}>
            <span style={styles.label}>Status:</span>
            <span style={{ ...styles.status, color: getStatusColor(job.status) }}>
              {job.status}
            </span>
          </div>
          <div style={styles.statusRow}>
            <span style={styles.label}>Analysis Method:</span>
            <span style={styles.value}>{job.intensity || 'standard'}</span>
          </div>
          {job.completed_at && (
            <div style={styles.statusRow}>
              <span style={styles.label}>Runtime:</span>
              <span style={styles.value}>
                {(() => {
                  const start = new Date(job.created_at).getTime();
                  const end = new Date(job.completed_at).getTime();
                  const seconds = Math.round((end - start) / 1000);
                  if (seconds < 60) return `${seconds}s`;
                  const mins = Math.floor(seconds / 60);
                  const secs = seconds % 60;
                  return `${mins}m ${secs}s`;
                })()}
              </span>
            </div>
          )}
          <div style={styles.statusRow}>
            <span style={styles.label}>Progress:</span>
            <span style={styles.value}>{job.progress}%</span>
          </div>
          <div style={styles.progressContainer}>
            <div
              style={{
                ...styles.progressBar,
                width: `${job.progress}%`,
              }}
            />
          </div>
          {job.error_message && (
            <div style={styles.errorMessage}>{job.error_message}</div>
          )}
        </div>

        <div style={styles.actions}>
          {job.status === 'completed' && report && (
            <>
              <button onClick={handleDownloadReport} style={styles.downloadButton}>
                Download Analysis Report (DOCX)
              </button>
              <button onClick={handleDownloadAnnotations} style={{...styles.downloadButton, background: '#238636', fontWeight: 'bold'}}>
                Download Annotated Code (TXT)
              </button>
              <button onClick={handleDownloadGhidraProject} style={{...styles.downloadButton, background: '#21262d'}}>
                Download Ghidra Database (ZIP)
              </button>
            </>
          )}
          {(job.status === 'queued' ||
            job.status === 'running' ||
            job.status === 'analyzing_ghidra' ||
            job.status === 'agent_running' ||
            job.status === 'report_writing') && (
            <button onClick={handleCancel} style={styles.cancelButton}>
              Cancel Analysis
            </button>
          )}
        </div>
      </div>

      <div style={styles.tabs}>
        <button
          onClick={() => setActiveTab('logs')}
          style={activeTab === 'logs' ? { ...styles.tab, ...styles.tabActive } : styles.tab}
        >
          Logs
        </button>
        {job.status === 'completed' && report && (
          <button
            onClick={() => setActiveTab('report')}
            style={activeTab === 'report' ? { ...styles.tab, ...styles.tabActive } : styles.tab}
          >
            Report
          </button>
        )}
      </div>

      <div style={styles.content}>
        {activeTab === 'logs' && (
          <div
            ref={logsContainerRef}
            onScroll={handleScroll}
            style={styles.logsContainer}
          >
            {logs.length === 0 ? (
              <p style={styles.emptyText}>No logs yet...</p>
            ) : (
              <>
                {logs.map((log, idx) => (
                  <div key={idx} style={styles.logLine}>
                    {log}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </>
            )}
          </div>
        )}

        {activeTab === 'report' && report && (
          <ReportViewer content={report} />
        )}
      </div>
    </div>
  );
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

const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '1000px',
    margin: '0 auto',
  },
  loading: {
    textAlign: 'center',
    color: '#8b949e',
    padding: '3rem',
  },
  error: {
    padding: '2rem',
    background: '#f85149',
    color: '#ffffff',
    borderRadius: '6px',
    textAlign: 'center',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: '2rem',
  },
  title: {
    color: '#c9d1d9',
    marginBottom: '0.5rem',
  },
  subtitle: {
    color: '#8b949e',
    fontSize: '0.9rem',
  },
  backButton: {
    padding: '0.5rem 1rem',
    background: '#21262d',
    color: '#c9d1d9',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  button: {
    marginTop: '1rem',
    padding: '0.75rem 1.5rem',
    background: '#238636',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  statusAndActions: {
    display: 'flex',
    gap: '1rem',
    alignItems: 'flex-start',
    marginBottom: '1rem',
  },
  statusCard: {
    flex: 1,
    padding: '1.5rem',
    background: '#161b22',
    borderRadius: '6px',
    border: '1px solid #30363d',
  },
  statusRow: {
    display: 'flex',
    gap: '0.5rem',
    marginBottom: '1rem',
  },
  label: {
    color: '#8b949e',
  },
  status: {
    fontWeight: 'bold',
  },
  value: {
    color: '#c9d1d9',
  },
  progressContainer: {
    width: '100%',
    height: '12px',
    background: '#21262d',
    borderRadius: '6px',
    overflow: 'hidden',
  },
  progressBar: {
    height: '100%',
    background: '#238636',
    transition: 'width 0.3s',
  },
  errorMessage: {
    marginTop: '1rem',
    padding: '1rem',
    background: '#f85149',
    color: '#ffffff',
    borderRadius: '6px',
  },
  actions: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  downloadButton: {
    padding: '0.75rem 1.5rem',
    background: '#238636',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  cancelButton: {
    padding: '0.75rem 1.5rem',
    background: '#da3633',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  tabs: {
    display: 'flex',
    borderBottom: '1px solid #30363d',
    marginBottom: '1rem',
  },
  tab: {
    padding: '0.75rem 1.5rem',
    background: 'transparent',
    color: '#8b949e',
    border: 'none',
    borderBottom: '2px solid transparent',
    cursor: 'pointer',
  },
  tabActive: {
    color: '#58a6ff',
    borderBottomColor: '#58a6ff',
  },
  content: {
    background: '#161b22',
    borderRadius: '6px',
    border: '1px solid #30363d',
    padding: '1.5rem',
  },
  logsContainer: {
    fontFamily: 'monospace',
    fontSize: '0.9rem',
    maxHeight: '500px',
    overflowY: 'auto',
  },
  logLine: {
    color: '#c9d1d9',
    marginBottom: '0.5rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
  },
  emptyText: {
    color: '#8b949e',
    textAlign: 'center',
  },
};

export default JobDetail;
