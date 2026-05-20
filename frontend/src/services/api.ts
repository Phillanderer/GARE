import { Job, JobListResponse, UploadResponse } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = {
  async uploadBinary(file: File, intensity: string = 'standard'): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('intensity', intensity);

    const response = await fetch(`${API_BASE}/api/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`Upload failed: ${response.statusText}`);
    }

    return response.json();
  },

  async listJobs(): Promise<JobListResponse> {
    const response = await fetch(`${API_BASE}/api/jobs`);

    if (!response.ok) {
      throw new Error(`Failed to fetch jobs: ${response.statusText}`);
    }

    return response.json();
  },

  async getJob(jobId: string): Promise<Job> {
    const response = await fetch(`${API_BASE}/api/jobs/${jobId}`);

    if (!response.ok) {
      throw new Error(`Failed to fetch job: ${response.statusText}`);
    }

    const data = await response.json();
    return data.job;
  },

  async getJobLogs(jobId: string): Promise<string[]> {
    const response = await fetch(`${API_BASE}/api/jobs/${jobId}/logs`);

    if (!response.ok) {
      throw new Error(`Failed to fetch logs: ${response.statusText}`);
    }

    const data = await response.json();
    return data.logs;
  },

  async getReport(jobId: string): Promise<string> {
    const response = await fetch(`${API_BASE}/api/jobs/${jobId}/report`);

    if (!response.ok) {
      throw new Error(`Failed to fetch report: ${response.statusText}`);
    }

    const data = await response.json();
    return data.content;
  },

  async downloadReport(jobId: string): Promise<void> {
    window.open(`${API_BASE}/api/jobs/${jobId}/report/docx`, '_blank');
  },

  async downloadGhidraProject(jobId: string): Promise<void> {
    window.open(`${API_BASE}/api/jobs/${jobId}/download/project`, '_blank');
  },

  async downloadAnnotations(jobId: string): Promise<void> {
    window.open(`${API_BASE}/api/jobs/${jobId}/download/annotations`, '_blank');
  },

  async cancelJob(jobId: string): Promise<void> {
    const response = await fetch(`${API_BASE}/api/jobs/${jobId}/cancel`, {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error(`Failed to cancel job: ${response.statusText}`);
    }
  },

  async deleteJob(jobId: string): Promise<void> {
    const response = await fetch(`${API_BASE}/api/jobs/${jobId}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error(`Failed to delete job: ${response.statusText}`);
    }
  },
};
