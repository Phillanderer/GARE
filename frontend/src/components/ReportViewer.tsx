import ReactMarkdown from 'react-markdown';

interface ReportViewerProps {
  content: string;
}

const ReportViewer = ({ content }: ReportViewerProps) => {
  return (
    <div style={styles.container}>
      <ReactMarkdown
        components={{
          h1: ({ children }) => <h1 style={styles.h1}>{children}</h1>,
          h2: ({ children }) => <h2 style={styles.h2}>{children}</h2>,
          h3: ({ children }) => <h3 style={styles.h3}>{children}</h3>,
          p: ({ children }) => <p style={styles.p}>{children}</p>,
          code: ({ children, className }) => {
            const isBlock = className?.includes('language-');
            return isBlock ? (
              <pre style={styles.pre}>
                <code style={styles.code}>{children}</code>
              </pre>
            ) : (
              <code style={styles.inlineCode}>{children}</code>
            );
          },
          ul: ({ children }) => <ul style={styles.ul}>{children}</ul>,
          ol: ({ children }) => <ol style={styles.ol}>{children}</ol>,
          li: ({ children }) => <li style={styles.li}>{children}</li>,
          table: ({ children }) => <table style={styles.table}>{children}</table>,
          thead: ({ children }) => <thead style={styles.thead}>{children}</thead>,
          th: ({ children }) => <th style={styles.th}>{children}</th>,
          td: ({ children }) => <td style={styles.td}>{children}</td>,
          blockquote: ({ children }) => <blockquote style={styles.blockquote}>{children}</blockquote>,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    color: '#c9d1d9',
    lineHeight: '1.6',
  },
  h1: {
    color: '#58a6ff',
    borderBottom: '2px solid #30363d',
    paddingBottom: '0.5rem',
    marginBottom: '1rem',
  },
  h2: {
    color: '#58a6ff',
    borderBottom: '1px solid #30363d',
    paddingBottom: '0.3rem',
    marginTop: '2rem',
    marginBottom: '1rem',
  },
  h3: {
    color: '#c9d1d9',
    marginTop: '1.5rem',
    marginBottom: '0.75rem',
  },
  p: {
    marginBottom: '1rem',
  },
  pre: {
    background: '#0d1117',
    padding: '1rem',
    borderRadius: '6px',
    border: '1px solid #30363d',
    overflowX: 'auto',
    marginBottom: '1rem',
  },
  code: {
    fontFamily: 'monospace',
    fontSize: '0.9rem',
    color: '#c9d1d9',
  },
  inlineCode: {
    fontFamily: 'monospace',
    background: '#0d1117',
    padding: '0.2rem 0.4rem',
    borderRadius: '3px',
    fontSize: '0.9rem',
    color: '#ff7b72',
  },
  ul: {
    marginBottom: '1rem',
    paddingLeft: '2rem',
  },
  ol: {
    marginBottom: '1rem',
    paddingLeft: '2rem',
  },
  li: {
    marginBottom: '0.5rem',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    marginBottom: '1rem',
  },
  thead: {
    borderBottom: '2px solid #30363d',
  },
  th: {
    padding: '0.75rem',
    textAlign: 'left',
    background: '#0d1117',
  },
  td: {
    padding: '0.75rem',
    borderBottom: '1px solid #30363d',
  },
  blockquote: {
    borderLeft: '4px solid #30363d',
    paddingLeft: '1rem',
    marginLeft: '0',
    color: '#8b949e',
    marginBottom: '1rem',
  },
};

export default ReportViewer;
