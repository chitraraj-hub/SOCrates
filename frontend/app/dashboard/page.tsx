// frontend/app/dashboard/page.tsx
"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { uploadLog, getJobResult, isLoggedIn, clearToken, JobResult } from "@/lib/api";

export default function DashboardPage() {
  const router  = useRouter();
  const fileRef = useRef<HTMLInputElement>(null);

  const [jobId,    setJobId]    = useState<string | null>(null);
  const [result,   setResult]   = useState<JobResult | null>(null);
  const [status,   setStatus]   = useState<string>("");
  const [error,    setError]    = useState<string>("");
  const [uploading, setUploading] = useState(false);

  // Redirect if not logged in
  useEffect(() => {
    if (!isLoggedIn()) router.push("/login");
  }, [router]);

  // Poll for results when jobId is set
  useEffect(() => {
    if (!jobId) return;

    const interval = setInterval(async () => {
      try {
        const data = await getJobResult(jobId);
        setStatus(data.status);

        if (data.status === "complete") {
          setResult(data);
          clearInterval(interval);
        } else if (data.status === "failed") {
          setError(data.error || "Pipeline failed");
          clearInterval(interval);
        }
      } catch {
        setError("Failed to fetch results");
        clearInterval(interval);
      }
    }, 2000); // poll every 2 seconds

    return () => clearInterval(interval);
  }, [jobId]);

  const handleUpload = async (file: File) => {
    setError("");
    setResult(null);
    setJobId(null);
    setUploading(true);
    setStatus("uploading");

    try {
      const res = await uploadLog(file);
      setJobId(res.job_id);
      setStatus("pending");
    } catch {
      setError("Upload failed");
    } finally {
      setUploading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleUpload(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) handleUpload(file);
  };

  const handleLogout = () => {
    clearToken();
    router.push("/login");
  };

  const severityColor = (severity: string) => ({
    critical: "text-red-400 bg-red-950 border-red-800",
    high:     "text-orange-400 bg-orange-950 border-orange-800",
    medium:   "text-yellow-400 bg-yellow-950 border-yellow-800",
    low:      "text-blue-400 bg-blue-950 border-blue-800",
  }[severity] || "text-gray-400 bg-gray-800 border-gray-700");

  const confidenceColor = (c: number) =>
    c >= 0.9 ? "text-red-400" :
    c >= 0.7 ? "text-orange-400" : "text-yellow-400";

  return (
    <div className="min-h-screen bg-gray-950 text-white">

      {/* Nav */}
      <nav className="border-b border-gray-800 px-6 py-4 flex justify-between items-center">
        <div>
          <span className="text-xl font-bold">SOCrates</span>
          <span className="text-gray-500 text-sm ml-3">Know your threats.</span>
        </div>
        <button
          onClick={handleLogout}
          className="text-gray-400 hover:text-white text-sm transition-colors"
        >
          Sign Out
        </button>
      </nav>

      <div className="max-w-5xl mx-auto px-6 py-8">

        {/* Upload area */}
        <div
          onDrop={handleDrop}
          onDragOver={(e) => e.preventDefault()}
          onClick={() => fileRef.current?.click()}
          className="border-2 border-dashed border-gray-700 hover:border-blue-500 rounded-lg p-10 text-center cursor-pointer transition-colors mb-8"
        >
          <input
            ref={fileRef}
            type="file"
            accept=".csv"
            onChange={handleFileChange}
            className="hidden"
          />
          <p className="text-gray-400">
            Drop a <span className="text-white font-medium">.csv</span> log file here or click to browse
          </p>
          <p className="text-gray-600 text-sm mt-1">ZScaler NSS Web Proxy format</p>
        </div>

        {/* Status */}
        {status && status !== "complete" && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6 flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
            <span className="text-gray-300 capitalize">{status}...</span>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="bg-red-950 border border-red-800 rounded-lg p-4 mb-6">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && result.anomalies && (
          <div>

            {/* Summary cards */}
            <div className="grid grid-cols-4 gap-4 mb-6">
              {[
                { label: "Total Logs",     value: result.total_logs?.toLocaleString() },
                { label: "Tier 1 Flagged", value: result.tier1_flagged },
                { label: "Tier 2 Flagged", value: result.tier2_flagged },
                { label: "Analysed In",    value: `${((result.total_time_ms || 0) / 1000).toFixed(1)}s` },
              ].map((card) => (
                <div key={card.label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                  <p className="text-gray-500 text-xs uppercase tracking-wide">{card.label}</p>
                  <p className="text-2xl font-bold text-white mt-1">{card.value}</p>
                </div>
              ))}
            </div>

            {/* Alert queue */}
            <h2 className="text-gray-400 text-sm uppercase tracking-wide mb-3">
              Alert Queue — {result.anomalies.length} anomalies ranked by confidence
            </h2>

            <div className="space-y-3">
              {result.anomalies.map((anomaly, i) => (
                <div
                  key={i}
                  className="bg-gray-900 border border-gray-800 rounded-lg p-4"
                >
                  {/* Header row */}
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(anomaly.severity)}`}>
                        {anomaly.severity.toUpperCase()}
                      </span>
                      <span className="text-white font-medium">{anomaly.domain}</span>
                      <span className="text-gray-500 text-sm">←</span>
                      <span className="text-gray-400 text-sm">{anomaly.src_ip}</span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className={`text-sm font-bold ${confidenceColor(anomaly.confidence)}`}>
                        {(anomaly.confidence * 100).toFixed(0)}%
                      </span>
                      <div className="flex gap-1">
                        {anomaly.tier1_fired && (
                          <span className="text-xs bg-purple-900 text-purple-300 border border-purple-700 px-1.5 py-0.5 rounded">T1</span>
                        )}
                        {anomaly.tier2_fired && (
                          <span className="text-xs bg-blue-900 text-blue-300 border border-blue-700 px-1.5 py-0.5 rounded">T2</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Threat summary */}
                  <p className="text-gray-300 text-sm mb-3">{anomaly.threat_summary}</p>

                  {/* Details — collapsed by default */}
                  <details className="group">
                    <summary className="text-gray-500 text-xs cursor-pointer hover:text-gray-300 transition-colors">
                      View full analysis ↓
                    </summary>
                    <div className="mt-3 space-y-3 border-t border-gray-800 pt-3">
                      <div>
                        <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">What Happened</p>
                        <p className="text-gray-300 text-sm">{anomaly.what_happened}</p>
                      </div>
                      <div>
                        <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Why Suspicious</p>
                        <p className="text-gray-300 text-sm">{anomaly.why_suspicious}</p>
                      </div>
                      <div>
                        <p className="text-gray-500 text-xs uppercase tracking-wide mb-1">Recommended Action</p>
                        <p className="text-gray-300 text-sm">{anomaly.recommended_action}</p>
                      </div>
                      <div className="flex gap-4 text-xs text-gray-500">
                        <span>User: <span className="text-gray-300">{anomaly.username}</span></span>
                        <span>IP: <span className="text-gray-300">{anomaly.src_ip}</span></span>
                      </div>
                    </div>
                  </details>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}