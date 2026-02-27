// frontend/lib/api.ts
//
// API client — wraps all backend calls with JWT auth header.
// NOTE: Prototype — token stored in localStorage.
// Production would use httpOnly cookies.

import axios from "axios";

const BASE_URL = "http://localhost:8000";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Token {
  access_token: string;
  token_type:   string;
  username:     string;
}

export interface UploadResponse {
  job_id:   string;
  filename: string;
  status:   string;
  message:  string;
}

export interface Anomaly {
  src_ip:             string;
  domain:             string;
  username:           string;
  threat_summary:     string;
  what_happened:      string;
  why_suspicious:     string;
  recommended_action: string;
  confidence:         number;
  severity:           string;
  tier1_fired:        boolean;
  tier2_fired:        boolean;
}

export interface JobResult {
  job_id:          string;
  status:          string;
  filename:        string;
  created_at:      string;
  total_logs:      number | null;
  tier1_flagged:   number | null;
  tier2_flagged:   number | null;
  tier3_explained: number | null;
  total_time_ms:   number | null;
  anomalies:       Anomaly[] | null;
  error:           string | null;
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

export const saveToken = (token: string) =>
  localStorage.setItem("socrates_token", token);

export const getToken = () =>
  localStorage.getItem("socrates_token");

export const clearToken = () =>
  localStorage.removeItem("socrates_token");

export const isLoggedIn = () =>
  !!getToken();

// ---------------------------------------------------------------------------
// Axios instance with auth header
// ---------------------------------------------------------------------------

const api = axios.create({ baseURL: BASE_URL });

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      clearToken();
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export const login = async (
  username: string,
  password: string
): Promise<Token> => {
  const form = new URLSearchParams();
  form.append("username", username);
  form.append("password", password);

  const res = await axios.post<Token>(
    `${BASE_URL}/auth/login`,
    form,
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  return res.data;
};

export const uploadLog = async (file: File): Promise<UploadResponse> => {
  const form = new FormData();
  form.append("file", file);
  const res = await api.post<UploadResponse>("/analysis/upload", form);
  return res.data;
};

export const getJobResult = async (jobId: string): Promise<JobResult> => {
  const res = await api.get<JobResult>(`/analysis/${jobId}`);
  return res.data;
};