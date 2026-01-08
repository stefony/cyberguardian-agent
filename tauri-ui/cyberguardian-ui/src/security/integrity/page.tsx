"use client";

import { useState, useEffect } from "react";
import { toast } from "sonner";
import { 
  Shield, 
  FileCheck, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  RefreshCw, 
  FileWarning,
  Lock,
  Unlock,
  Eye,
  Fingerprint,
  ShieldAlert,
  Activity
} from "lucide-react";
import ProtectedRoute from '@/components/ProtectedRoute';

// API configuration
const API_URL = process.env.NEXT_PUBLIC_API_URL ||'http://localhost:8000';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string, options?: RequestInit) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers: {
      ...headers,
      ...(options?.headers || {}),
    }
  });
  return response.json();
};

interface IntegrityStats {
  total_checks: number;
  status_counts: {
    OK?: number;
    MODIFIED?: number;
    MISSING?: number;
    ERROR?: number;
  };
  active_alerts: number;
  recent_compromised: number;
  total_manifests: number;
}

interface IntegrityLog {
  id: number;
  file_path: string;
  expected_checksum: string;
  actual_checksum: string | null;
  status: string;
  timestamp: string;
  details: string | null;
}

interface IntegrityAlert {
  id: number;
  alert_type: string;
  severity: string;
  file_path: string | null;
  message: string;
  resolved: boolean;
  created_at: string;
  resolved_at: string | null;
}

interface ManifestInfo {
  id: number;
  version: string;
  created_at: string;
  total_files: number;
}

export default function IntegrityMonitoringPage() {
  const [stats, setStats] = useState<IntegrityStats | null>(null);
  const [logs, setLogs] = useState<IntegrityLog[]>([]);
  const [alerts, setAlerts] = useState<IntegrityAlert[]>([]);
  const [manifest, setManifest] = useState<ManifestInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [overallHealth, setOverallHealth] = useState<"HEALTHY" | "WARNING" | "CRITICAL">("HEALTHY");


  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Calculate overall health
    if (stats) {
      const compromised = (stats.status_counts?.MODIFIED || 0) + (stats.status_counts?.MISSING || 0);
      if (compromised > 0 || stats.active_alerts > 0) {
        setOverallHealth("CRITICAL");
      } else if (stats.total_checks === 0) {
        setOverallHealth("WARNING");
      } else {
        setOverallHealth("HEALTHY");
      }
    }
  }, [stats]);

  const fetchData = async () => {
  try {
    const [statsData, manifestData, logsData, alertsData] = await Promise.all([
      fetchWithAuth('/api/integrity/statistics'),
      fetchWithAuth('/api/integrity/manifest/latest'),
      fetchWithAuth('/api/integrity/logs?limit=20'),
      fetchWithAuth('/api/integrity/alerts?resolved=false')
    ]);

    if (statsData.success) setStats(statsData.statistics);
    if (manifestData.success && manifestData.manifest) setManifest(manifestData.manifest);
    if (logsData.success) setLogs(logsData.logs);
    if (alertsData.success) setAlerts(alertsData.alerts);
  } catch (error) {
    console.error("Error fetching data:", error);
  }
};

  const generateManifest = async () => {
  setGenerating(true);
  try {
    const data = await fetchWithAuth('/api/integrity/manifest/generate', {
      method: "POST",
    });

    if (data.success) {
      toast.success("✅ Manifest Generated", {
        description: `Checksums created for ${data.manifest.total_files} files`,
      });
      fetchData();
    } else {
      toast.error("Failed to generate manifest");
    }
  } catch (error) {
    console.error("Error generating manifest:", error);
    toast.error("Failed to generate manifest");
  } finally {
    setGenerating(false);
  }
};

  const verifyAllFiles = async () => {
  setVerifying(true);
  toast.info("🔍 Scanning files...", { description: "This may take a moment" });
  
  try {
    const data = await fetchWithAuth('/api/integrity/verify/all', {
      method: "POST",
    });

    if (data.success) {
      const report = data.report;
      
      if (report.overall_status === "HEALTHY") {
        toast.success("✅ Integrity Verified", {
          description: `All ${report.ok} files are intact and unmodified`,
        });
      } else {
        toast.error("🚨 Integrity Compromised", {
          description: `${report.modified} modified • ${report.missing} missing files`,
        });
      }
      
      fetchData();
    } else {
      toast.error("Verification failed");
    }
  } catch (error) {
    console.error("Error verifying files:", error);
    toast.error("Failed to verify files");
  } finally {
    setVerifying(false);
  }
};

  const resolveAlert = async (alertId: number) => {
  try {
    const data = await fetchWithAuth(`/api/integrity/alerts/${alertId}/resolve`, {
      method: "POST",
    });

    if (data.success) {
      toast.success("Alert resolved");
      fetchData();
    }
  } catch (error) {
    console.error("Error resolving alert:", error);
    toast.error("Failed to resolve alert");
  }
};

  const getStatusColor = (status: string) => {
    switch (status) {
      case "OK":
        return "text-emerald-600 bg-emerald-50 border-emerald-200";
      case "MODIFIED":
        return "text-amber-600 bg-amber-50 border-amber-200";
      case "MISSING":
        return "text-rose-600 bg-rose-50 border-rose-200";
      case "ERROR":
        return "text-gray-600 bg-gray-50 border-gray-200";
      default:
        return "text-gray-600 bg-gray-50 border-gray-200";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "text-rose-600 bg-rose-50 border-rose-200";
      case "HIGH":
        return "text-orange-600 bg-orange-50 border-orange-200";
      case "MEDIUM":
        return "text-amber-600 bg-amber-50 border-amber-200";
      case "LOW":
        return "text-blue-600 bg-blue-50 border-blue-200";
      default:
        return "text-gray-600 bg-gray-50 border-gray-200";
    }
  };

  const getHealthGradient = () => {
    switch (overallHealth) {
      case "HEALTHY":
        return "from-emerald-400 via-teal-400 to-cyan-500";
      case "WARNING":
        return "from-amber-400 via-orange-400 to-red-400";
      case "CRITICAL":
        return "from-rose-500 via-red-500 to-pink-600";
    }
  };

  const getHealthIcon = () => {
    switch (overallHealth) {
      case "HEALTHY":
        return <Shield className="w-20 h-20 text-white drop-shadow-lg animate-pulse" />;
      case "WARNING":
        return <ShieldAlert className="w-20 h-20 text-white drop-shadow-lg animate-pulse" />;
      case "CRITICAL":
        return <AlertTriangle className="w-20 h-20 text-white drop-shadow-lg animate-bounce" />;
    }
  };

  return (
    <ProtectedRoute>
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Hero Section with Health Status */}
        <div className={`relative bg-gradient-to-r ${getHealthGradient()} rounded-3xl p-12 shadow-2xl overflow-hidden`}>
          {/* Animated Background Pattern */}
          <div className="absolute inset-0 opacity-10">
            <div className="absolute top-0 left-0 w-96 h-96 bg-white rounded-full blur-3xl animate-pulse"></div>
            <div className="absolute bottom-0 right-0 w-96 h-96 bg-white rounded-full blur-3xl animate-pulse delay-1000"></div>
          </div>
          
          <div className="relative z-10 flex items-center justify-between">
            <div className="flex items-center gap-8">
              {/* Animated Shield Icon */}
              <div className="relative">
                <div className="absolute inset-0 bg-white/20 rounded-full blur-xl animate-ping"></div>
                {getHealthIcon()}
              </div>
              
              <div>
                <h1 className="text-5xl font-black text-white mb-3 tracking-tight">
                  System Integrity
                </h1>
                <p className="text-2xl font-semibold text-white/90 mb-2">
                  {overallHealth === "HEALTHY" && "✅ All Systems Secure"}
                  {overallHealth === "WARNING" && "⚠️ Monitoring Required"}
                  {overallHealth === "CRITICAL" && "🚨 Security Alert"}
                </p>
                <p className="text-white/80 text-lg">
                  Real-time file integrity monitoring & tamper detection
                </p>
              </div>
            </div>
            
            {/* Action Buttons */}
            <div className="flex flex-col gap-3">
              <button
                onClick={generateManifest}
                disabled={generating}
                className="px-8 py-4 bg-white/20 backdrop-blur-lg text-white rounded-2xl hover:bg-white/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-3 border border-white/30 shadow-xl"
              >
                {generating ? (
                  <>
                    <RefreshCw className="w-6 h-6 animate-spin" />
                    <span className="font-semibold">Generating...</span>
                  </>
                ) : (
                  <>
                    <Fingerprint className="w-6 h-6" />
                    <span className="font-semibold">Generate Manifest</span>
                  </>
                )}
              </button>

              <button
                onClick={verifyAllFiles}
                disabled={verifying || !manifest}
                className="px-8 py-4 bg-white text-purple-600 rounded-2xl hover:shadow-2xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-3 font-bold"
              >
                {verifying ? (
                  <>
                    <RefreshCw className="w-6 h-6 animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Eye className="w-6 h-6" />
                    <span>Verify All Files</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Statistics Grid - Glassmorphism Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Total Checks */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <Activity className="w-8 h-8 text-blue-400" />
                <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">📊</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Total Checks</p>
              <p className="text-4xl font-black text-white">
                {stats?.total_checks || 0}
              </p>
            </div>
          </div>

          {/* Files OK */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/20 to-teal-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                <div className="w-12 h-12 bg-emerald-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">✅</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Files Verified</p>
              <p className="text-4xl font-black text-emerald-400">
                {stats?.status_counts?.OK || 0}
              </p>
            </div>
          </div>

          {/* Active Alerts */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-rose-500/20 to-pink-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <AlertTriangle className="w-8 h-8 text-rose-400" />
                <div className="w-12 h-12 bg-rose-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">🚨</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Active Alerts</p>
              <p className="text-4xl font-black text-rose-400">
                {stats?.active_alerts || 0}
              </p>
            </div>
          </div>

          {/* Compromised Files */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-amber-500/20 to-orange-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <FileWarning className="w-8 h-8 text-amber-400" />
                <div className="w-12 h-12 bg-amber-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">⚠️</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Compromised</p>
              <p className="text-4xl font-black text-amber-400">
                {(stats?.status_counts?.MODIFIED || 0) + (stats?.status_counts?.MISSING || 0)}
              </p>
            </div>
          </div>
        </div>

        {/* Manifest Info Card */}
        {manifest && (
          <div className="relative bg-gradient-to-br from-purple-600/30 via-pink-600/30 to-rose-600/30 backdrop-blur-xl rounded-3xl p-8 border border-white/20 shadow-2xl overflow-hidden">
            <div className="absolute inset-0 bg-white/5"></div>
            <div className="relative z-10 flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div className="w-20 h-20 bg-white/20 rounded-2xl flex items-center justify-center backdrop-blur-lg">
                  <Lock className="w-10 h-10 text-white" />
                </div>
                <div>
                  <p className="text-purple-200 font-semibold text-sm mb-1">🔐 Active Manifest</p>
                  <p className="text-3xl font-black text-white mb-2">Version {manifest.version}</p>
                  <p className="text-white/80 text-sm">
                    <span className="font-semibold">{manifest.total_files}</span> files under protection • 
                    Created {new Date(manifest.created_at).toLocaleDateString()} at {new Date(manifest.created_at).toLocaleTimeString()}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <div className="inline-block px-6 py-3 bg-white/20 backdrop-blur-lg rounded-xl border border-white/30">
                  <p className="text-xs text-white/70 mb-1">Integrity Status</p>
                  <p className="text-2xl font-black text-white">ACTIVE</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Active Alerts Section */}
        {alerts.length > 0 && (
          <div className="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 overflow-hidden shadow-2xl">
            <div className="bg-gradient-to-r from-rose-600/50 to-pink-600/50 p-6 border-b border-white/10">
              <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                <ShieldAlert className="w-7 h-7" />
                Active Security Alerts
                <span className="ml-auto px-4 py-2 bg-white/20 rounded-xl text-sm font-black">
                  {alerts.length}
                </span>
              </h2>
            </div>
            <div className="divide-y divide-white/10">
              {alerts.map((alert) => (
                <div key={alert.id} className="p-6 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <span className={`px-4 py-2 rounded-xl text-xs font-bold border ${getSeverityColor(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="text-sm text-gray-300 font-medium">
                          {alert.alert_type.replace(/_/g, " ")}
                        </span>
                      </div>
                      <p className="text-white font-semibold text-lg mb-2">{alert.message}</p>
                      {alert.file_path && (
                        <p className="text-sm text-purple-300 font-mono bg-white/5 px-3 py-2 rounded-lg inline-block">
                          📁 {alert.file_path}
                        </p>
                      )}
                      <p className="text-xs text-gray-400 mt-3">
                        🕐 {new Date(alert.created_at).toLocaleString()}
                      </p>
                    </div>
                    <button
                      onClick={() => resolveAlert(alert.id)}
                      className="ml-6 px-6 py-3 bg-emerald-500 text-white rounded-xl hover:bg-emerald-600 transition-all shadow-lg hover:shadow-emerald-500/50 font-bold"
                    >
                      ✓ Resolve
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent Logs Table */}
        <div className="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 overflow-hidden shadow-2xl">
          <div className="bg-gradient-to-r from-indigo-600/50 to-purple-600/50 p-6 border-b border-white/10">
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <Clock className="w-7 h-7" />
              Recent Integrity Checks
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-white/5">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-bold text-purple-300 uppercase tracking-wider">
                    File Path
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-purple-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-purple-300 uppercase tracking-wider">
                    Checksum
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-purple-300 uppercase tracking-wider">
                    Timestamp
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center gap-4">
                        <FileCheck className="w-16 h-16 text-purple-400 opacity-50" />
                        <p className="text-gray-300 text-lg">No integrity checks performed yet</p>
                        <p className="text-gray-400 text-sm">Generate a manifest and verify files to get started</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.id} className="hover:bg-white/5 transition-colors">
                      <td className="px-6 py-4">
                        <p className="text-sm font-mono text-white">{log.file_path}</p>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1.5 rounded-lg text-xs font-bold border ${getStatusColor(log.status)}`}>
                          {log.status}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <p className="text-xs font-mono text-purple-300">
                          {log.actual_checksum ? log.actual_checksum.substring(0, 16) + "..." : "N/A"}
                        </p>
                      </td>
                      <td className="px-6 py-4">
                        <p className="text-sm text-gray-300">
                          {new Date(log.timestamp).toLocaleString()}
                        </p>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
    </ProtectedRoute>
  );
}