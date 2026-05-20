export type JobStatus =
  | 'queued'
  | 'running'
  | 'analyzing_ghidra'
  | 'agent_running'
  | 'report_writing'
  | 'completed'
  | 'failed'
  | 'canceled';

export interface Job {
  id: string;
  filename: string;
  sha256: string;
  created_at: string;
  completed_at?: string;
  status: JobStatus;
  progress: number;
  intensity?: string;
  error_message?: string;
  artifacts: string[];
  logs: string[];
}

export interface JobListResponse {
  jobs: Job[];
  total: number;
}

export interface UploadResponse {
  job_id: string;
  filename: string;
  sha256: string;
  message: string;
}
