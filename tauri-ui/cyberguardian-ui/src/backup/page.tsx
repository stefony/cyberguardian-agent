"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield, HardDrive, Clock, AlertTriangle, CheckCircle,
  XCircle, RefreshCw, Database, Lock, Loader2, Activity
} from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { httpFetch } from "@/lib/api";
import { toast } from "sonner";
import ProtectedRoute from "@/components/ProtectedRoute";

// ============================================
// TYPES
// ============================================

type BackupSolution = {
  name: string;
  vendor: string;
  detection_method: string;
  status: string;
  version?: string;
};

type VssStatus = {
  service_running: boolean;
  snapshot_count: number;
  last_snapshot?: string;
  protection_status: string;
};

type BackupFreshness = {
  last_backup_time?: string;
  age_hours?: number;
  status: string;
  frequency: string;
};

type RansomwareThreat = {
  detected: boolean;
  threat_type: string;
  command_detected?: string;
  timestamp?: string;
  severity: string;
};

type ComplianceDetail = {
  article: string;
  requirement: string;
  status: string;
  score: number;
  finding: string;
};

type BackupReport = {
  timestamp: string;
  solutions: BackupSolution[];
  vss_status: VssStatus;
  freshness: BackupFreshness;
  ransomware_threats: RansomwareThreat[];
  nis2_score: number;
  nis2_status: string;
  compliance_details: ComplianceDetail[];
  recommendations: string[];
};

type BackendStatus = {
  has_data: boolean;
  nis2_score: number;
  nis2_status: string;
  solutions: BackupSolution[];
  vss_status: VssStatus;
  freshness: BackupFreshness;
  ransomware_threats: RansomwareThreat[];
  compliance_details: ComplianceDetail[];
  recommendations: string[];
  last_scan?: string;
};

// ============================================
// HELPERS
// ============================================

const getScoreColor = (score: number) => {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  return "text-red-400";
};

const getScoreBg = (score: number) => {
  if (score >= 80) return "bg-green-500";
  if (score >= 60) return "bg-yellow-500";
  return "bg-red-500";
};

const getStatusIcon = (status: string) => {
  if (status === "compliant" || status === "ok" || status === "running" || status === "active")
    return <CheckCircle className="h-4 w-4 text-green-400" />;
  if (status === "warning" || status === "stale")
    return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
  return <XCircle className="h-4 w-4 text-red-400" />;
};

const getStatusBadge = (status: string) => {
  if (status === "compliant" || status === "fresh" || status === "protected")
    return "px-2 py-0.5 rounded text-xs font-bold bg-green-500/10 text-green-400 border border-green-500/20";
  if (status === "warning" || status === "stale" || status === "at_risk")
    return "px-2 py-0.5 rounded text-xs font-bold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";
  return "px-2 py-0.5 rounded text-xs font-bold bg-red-500/10 text-red-400 border border-red-500/20";
};

// ============================================
// COMPONENT
// ============================================

export default function BackupSecurityPage() {
  const [scanning, setScanning]         = useState(false);
  const [backendData, setBackendData]   = useState<BackendStatus | null>(null);
  const [localReport, setLocalReport]   = useState<BackupReport | null>(null);
  const [error, setError]               = useState<string | null>(null);
  const [lastScan, setLastScan]         = useState<string | null>(null);

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    "Authorization": `Bearer ${localStorage.getItem("access_token") || ""}`,
  });

  // Load latest status from backend on mount
  const loadBackendStatus = useCallback(async () => {
    try {
      const response = await httpFetch("/api/backup/status", {
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      if (data.success) {
        setBackendData(data);
      }
    } catch (err) {
      console.error("Failed to load backup status:", err);
    }
  }, []);

  useEffect(() => {
    loadBackendStatus();
  }, [loadBackendStatus]);

  // Run full scan via Tauri agent
  const runScan = async () => {
    setScanning(true);
    setError(null);

    try {
      // 1. Run Rust agent scan
      const report = await invoke<BackupReport>("scan_backup_security");
      setLocalReport(report);
      setLastScan(new Date().toLocaleString());

      // 2. Send to backend
      const response = await httpFetch("/api/backup/report", {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(report),
      });

      const result = await response.json();

      if (result.success) {
        toast.success("Backup scan completed", {
          description: `NIS2 Score: ${report.nis2_score}% — ${report.nis2_status.toUpperCase()}`,
          duration: 5000,
        });

        // Alert if ransomware threats detected
        if (report.ransomware_threats.length > 0) {
          toast.error("🚨 Ransomware backup attack detected!", {
            description: `${report.ransomware_threats.length} threat(s) found — immediate action required`,
            duration: 10000,
          });
        }

        // Reload backend data
        await loadBackendStatus();
      }

    } catch (err: any) {
      setError(err.message || "Scan failed");
      toast.error("Backup scan failed", { description: err.message });
    } finally {
      setScanning(false);
    }
  };

  // Use local report if available, otherwise backend data
  const displayData = localReport ? {
    nis2_score:          localReport.nis2_score,
    nis2_status:         localReport.nis2_status,
    solutions:           localReport.solutions,
    vss_status:          localReport.vss_status,
    freshness:           localReport.freshness,
    ransomware_threats:  localReport.ransomware_threats,
    compliance_details:  localReport.compliance_details,
    recommendations:     localReport.recommendations,
  } : backendData;

  const score = displayData?.nis2_score ?? 0;

  return (
    <ProtectedRoute>
      <main className="pb-12">

        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  NIS2 Art. 21(2)(c)
                </span>
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30">
                  BACKUP SECURITY
                </span>
              </div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                Backup Security Monitor
              </h1>
              <p className="mt-2 text-muted-foreground">
                Business continuity &amp; backup posture monitoring for NIS2 compliance
              </p>
              {lastScan && (
                <p className="text-xs text-muted-foreground mt-1">
                  Last scan: {lastScan}
                </p>
              )}
              {backendData?.last_scan && !lastScan && (
                <p className="text-xs text-muted-foreground mt-1">
                  Last scan: {new Date(backendData.last_scan).toLocaleString()}
                </p>
              )}
            </div>

            <div className="flex items-center gap-4">
              {/* NIS2 Score */}
              <div className="text-right">
                <div className={`text-5xl font-bold ${getScoreColor(score)}`}>
                  {score}%
                </div>
                <div className="text-xs text-muted-foreground mt-1">NIS2 Art. 21(2)(c)</div>
              </div>

              {/* Scan Button */}
              <button
                onClick={runScan}
                disabled={scanning}
                className="px-5 py-2.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {scanning
                  ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</>
                  : <><RefreshCw className="h-4 w-4" />Run Scan</>
                }
              </button>
            </div>
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="page-container mt-4">
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-between">
              <span className="text-sm text-red-400">⚠ {error}</span>
              <button onClick={() => setError(null)} className="text-red-400 text-xs">Dismiss</button>
            </div>
          </div>
        )}

        {/* Ransomware Alert */}
        {displayData && displayData.ransomware_threats.length > 0 && (
          <div className="page-container mt-4">
            <div className="p-4 rounded-lg bg-red-500/10 border-2 border-red-500/50 animate-pulse">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-6 w-6 text-red-400 flex-shrink-0" />
                <div>
                  <div className="font-bold text-red-400">
                    🚨 RANSOMWARE BACKUP ATTACK DETECTED
                  </div>
                  <div className="text-sm text-red-300 mt-1">
                    {displayData.ransomware_threats.map((t, i) => (
                      <div key={i}>{t.threat_type}: <code className="text-xs">{t.command_detected}</code></div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="section space-y-6">

          {/* No data state */}
          {!displayData && !scanning && (
            <div className="card-premium p-12 text-center">
              <HardDrive className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Backup Data Available</h3>
              <p className="text-sm text-muted-foreground mb-6">
                Run a scan to check your backup security posture and NIS2 compliance
              </p>
              <button
                onClick={runScan}
                className="px-6 py-3 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors"
              >
                Run First Scan
              </button>
            </div>
          )}

          {displayData && (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Database className="h-4 w-4 text-blue-400" />
                    <span className="text-sm text-muted-foreground">Solutions</span>
                  </div>
                  <div className="text-2xl font-bold text-blue-400">
                    {displayData.solutions.length}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {displayData.solutions.length > 0 ? "Detected" : "None found"}
                  </div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="h-4 w-4 text-purple-400" />
                    <span className="text-sm text-muted-foreground">VSS Snapshots</span>
                  </div>
                  <div className="text-2xl font-bold text-purple-400">
                    {displayData.vss_status.snapshot_count}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {displayData.vss_status.service_running ? "Service running" : "Service stopped"}
                  </div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Clock className="h-4 w-4 text-green-400" />
                    <span className="text-sm text-muted-foreground">Backup Status</span>
                  </div>
                  <div className={`text-2xl font-bold ${
                    displayData.freshness.status === "fresh" ? "text-green-400" :
                    displayData.freshness.status === "stale" ? "text-yellow-400" : "text-red-400"
                  }`}>
                    {displayData.freshness.status.toUpperCase()}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {displayData.freshness.frequency}
                  </div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Lock className="h-4 w-4 text-orange-400" />
                    <span className="text-sm text-muted-foreground">Ransomware Threats</span>
                  </div>
                  <div className={`text-2xl font-bold ${
                    displayData.ransomware_threats.length === 0 ? "text-green-400" : "text-red-400"
                  }`}>
                    {displayData.ransomware_threats.length}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {displayData.ransomware_threats.length === 0 ? "Clean" : "Detected!"}
                  </div>
                </div>
              </div>

              {/* Backup Solutions */}
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <Database className="h-5 w-5 text-blue-500" />
                  Detected Backup Solutions
                </h2>
                {displayData.solutions.length === 0 ? (
                  <div className="p-4 rounded-lg bg-red-500/5 border border-red-500/20">
                    <p className="text-sm text-red-400">
                      ⚠ No backup solution detected — critical NIS2 Art. 21(2)(c) gap
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {displayData.solutions.map((sol, i) => (
                      <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-muted/10 border border-border">
                        <div className="flex items-center gap-3">
                          {getStatusIcon(sol.status)}
                          <div>
                            <div className="font-medium text-sm">{sol.name}</div>
                            <div className="text-xs text-muted-foreground">
                              {sol.vendor} · via {sol.detection_method}
                            </div>
                          </div>
                        </div>
                        <span className={getStatusBadge(sol.status)}>{sol.status}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* VSS Status */}
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <Shield className="h-5 w-5 text-purple-500" />
                  Volume Shadow Copy (VSS) Status
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 rounded-lg bg-muted/10 border border-border">
                    <div className="text-xs text-muted-foreground mb-1">VSS Service</div>
                    <div className="flex items-center gap-2">
                      {displayData.vss_status.service_running
                        ? <CheckCircle className="h-4 w-4 text-green-400" />
                        : <XCircle className="h-4 w-4 text-red-400" />
                      }
                      <span className={`font-semibold ${displayData.vss_status.service_running ? "text-green-400" : "text-red-400"}`}>
                        {displayData.vss_status.service_running ? "Running" : "Stopped"}
                      </span>
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-muted/10 border border-border">
                    <div className="text-xs text-muted-foreground mb-1">Shadow Copies</div>
                    <div className="font-semibold text-purple-400">
                      {displayData.vss_status.snapshot_count} snapshots
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-muted/10 border border-border">
                    <div className="text-xs text-muted-foreground mb-1">Protection Status</div>
                    <span className={getStatusBadge(displayData.vss_status.protection_status)}>
                      {displayData.vss_status.protection_status}
                    </span>
                  </div>
                </div>
                {displayData.vss_status.last_snapshot && (
                  <div className="mt-3 text-xs text-muted-foreground">
                    Last snapshot: {displayData.vss_status.last_snapshot}
                  </div>
                )}
              </div>

              {/* NIS2 Compliance Details */}
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <Activity className="h-5 w-5 text-blue-500" />
                  NIS2 Art. 21(2)(c) — Compliance Details
                </h2>
                <div className="space-y-3">
                  {displayData.compliance_details.map((detail, i) => (
                    <div key={i} className="flex items-start gap-4">
                      {getStatusIcon(detail.status)}
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium">{detail.requirement}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">{detail.article}</span>
                            <span className={`font-bold text-sm ${getScoreColor(detail.score)}`}>
                              {detail.score}%
                            </span>
                          </div>
                        </div>
                        <div className="h-1.5 w-full rounded-full bg-muted/30 mb-1">
                          <div
                            className={`h-full rounded-full ${getScoreBg(detail.score)}`}
                            style={{ width: `${detail.score}%` }}
                          />
                        </div>
                        <div className="text-xs text-muted-foreground">{detail.finding}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommendations */}
              {displayData.recommendations.length > 0 && (
                <div className="card-premium p-6">
                  <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                    Recommendations
                  </h2>
                  <div className="space-y-3">
                    {displayData.recommendations.map((rec, i) => {
                      const isCritical = rec.startsWith("CRITICAL");
                      const isHigh     = rec.startsWith("HIGH");
                      return (
                        <div key={i} className={`p-4 rounded-lg border ${
                          isCritical ? "bg-red-500/5 border-red-500/20" :
                          isHigh     ? "bg-orange-500/5 border-orange-500/20" :
                                       "bg-yellow-500/5 border-yellow-500/20"
                        }`}>
                          <p className={`text-sm ${
                            isCritical ? "text-red-400" :
                            isHigh     ? "text-orange-400" :
                                         "text-yellow-400"
                          }`}>
                            {rec}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          )}

        </div>
      </main>
    </ProtectedRoute>
  );
}