import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import UploadView from './components/UploadView';
import JobsList from './components/JobsList';
import JobDetail from './components/JobDetail';

const App = () => {
  // Prevent default drag and drop behavior outside designated drop zones
  useEffect(() => {
    const preventDefaults = (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
    };

    // Prevent browser from opening files dropped outside drop zones
    window.addEventListener('dragover', preventDefaults);
    window.addEventListener('drop', preventDefaults);

    return () => {
      window.removeEventListener('dragover', preventDefaults);
      window.removeEventListener('drop', preventDefaults);
    };
  }, []);

  return (
    <BrowserRouter>
      <div style={styles.container}>
        <header style={styles.header}>
          <h1 style={styles.title}>Ghidra Agentic RE Pipeline</h1>
          <nav style={styles.nav}>
            <Link to="/" style={styles.link}>Upload</Link>
            <Link to="/jobs" style={styles.link}>Jobs</Link>
          </nav>
        </header>

        <main style={styles.main}>
          <Routes>
            <Route path="/" element={<UploadView />} />
            <Route path="/jobs" element={<JobsList />} />
            <Route path="/jobs/:jobId" element={<JobDetail />} />
          </Routes>
        </main>

        <footer style={styles.footer}>
          <p>Automated Reverse Engineering with Ghidra and LLM Agents</p>
        </footer>
      </div>
    </BrowserRouter>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    background: '#161b22',
    padding: '1rem 2rem',
    borderBottom: '1px solid #30363d',
    textAlign: 'center',
  },
  title: {
    color: '#58a6ff',
    marginBottom: '0.5rem',
  },
  nav: {
    display: 'flex',
    gap: '1rem',
    justifyContent: 'center',
  },
  link: {
    color: '#8b949e',
    textDecoration: 'none',
    padding: '0.5rem 1rem',
    borderRadius: '6px',
    transition: 'background 0.2s',
  },
  main: {
    flex: 1,
    padding: '2rem',
    maxWidth: '1200px',
    margin: '0 auto',
    width: '100%',
  },
  footer: {
    background: '#161b22',
    padding: '1rem',
    textAlign: 'center',
    borderTop: '1px solid #30363d',
    color: '#8b949e',
  },
};

export default App;
