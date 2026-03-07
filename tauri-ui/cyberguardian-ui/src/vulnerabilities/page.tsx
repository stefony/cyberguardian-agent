"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield, AlertTriangle, CheckCircle, XCircle,
  RefreshCw, Loader2, Bug, Package, Search,
  ChevronDown, ChevronUp, ExternalLink
} from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { httpFetch } from "@/lib/api";
import { toast } from "sonner";
import ProtectedRoute from "@/components/ProtectedRoute";

// ============================================
// TYPES
// ============================================

type InstalledSoftware = {
  name: string;
  version: string;
  publisher?: string;
  install_date?: string;
};

type VulnerabilityFinding = {
  software_name: string;
  software_version: string;
  cve_id: string;
  cvss_score: number;
  severity: string;
  description: string;
  published_date?: string;
  patch_available: boolean;
  remediation: string;
};

type VulnScanResult = {
  timestamp: string;
  hostname: string;
  software_count: number;
  scanned_software: InstalledSoftware[];
  vulnerabilities: VulnerabilityFinding[];
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  nis2_score: number;
  nis2_status: string;
  zks_article: string;
  recommendations: string[];
};

type BackendStatus = {
  has_data: boolean;
  hostname?: string;
  software_count?: number;
  vulnerabilities: VulnerabilityFinding[];
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  nis2_score: number;
  nis2_status: string;
  recommendations: string[];
  zks_article?: string;
  last_scan?: string;
};

// ============================================
// HELPERS
// ============================================

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case "critical": return "text-red-400";
    case "high":     return "text-orange-400";
    case "medium":   return "text-yellow-400";
    case "low":      return "text-blue-400";
    default:         return "text-muted-foreground";
  }
};

const getSeverityBg = (severity: string) => {
  switch (severity) {
    case "critical": return "bg-red-500/10 border-red-500/30 text-red-400";
    case "high":     return "bg-orange-500/10 border-orange-500/30 text-orange-400";
    case "medium":   return "bg-yellow-500/10 border-yellow-500/30 text-yellow-400";
    case "low":      return "bg-blue-500/10 border-blue-500/30 text-blue-400";
    default:         return "bg-muted/10 border-border text-muted-foreground";
  }
};

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

const getCvssColor = (score: number) => {
  if (score >= 9.0) return "text-red-400 font-bold";
  if (score >= 7.0) return "text-orange-400 font-bold";
  if (score >= 4.0) return "text-yellow-400";
  return "text-blue-400";
};

// ============================================
// COMPONENT
// ============================================

export default function VulnerabilitiesPage() {
  const [scanning, setScanning]           = useState(false);
  const [analyzingCves, setAnalyzingCves] = useState(false);
  const [backendData, setBackendData]     = useState<BackendStatus | null>(null);
  const [localScan, setLocalScan]         = useState<VulnScanResult | null>(null);
  const [error, setError]                 = useState<string | null>(null);
  const [lastScan, setLastScan]           = useState<string | null>(null);
  const [searchQuery, setSearchQuery]     = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [expandedCve, setExpandedCve]     = useState<string | null>(null);
  const [activeTab, setActiveTab]         = useState<"vulnerabilities" | "software">("vulnerabilities");

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    "Authorization": `Bearer ${localStorage.getItem("access_token") || ""}`,
  });

  // Load backend status on mount
  const loadBackendStatus = useCallback(async () => {
    try {
      const response = await httpFetch("/api/vulnerabilities/status", {
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      if (data.success) setBackendData(data);
    } catch (err) {
      console.error("Failed to load vuln status:", err);
    }
  }, []);

  useEffect(() => {
    loadBackendStatus();
  }, [loadBackendStatus]);

  // Step 1: Run local registry scan
  const runLocalScan = async () => {
    setScanning(true);
    setError(null);

    try {
      const result = await invoke<VulnScanResult>("scan_vulnerabilities");
      setLocalScan(result);
      setLastScan(new Date().toLocaleString());

      toast.success("Software inventory complete", {
        description: `${result.software_count} packages found on ${result.hostname}`,
        duration: 4000,
      });

      // Step 2: Send to backend for CVE matching
      await runCveAnalysis(result);

    } catch (err: any) {
      setError(err.message || "Scan failed");
      toast.error("Scan failed", { description: err.message });
    } finally {
      setScanning(false);
    }
  };

  // Step 2: CVE analysis via backend NVD API
  const runCveAnalysis = async (scan: VulnScanResult) => {
    setAnalyzingCves(true);

    try {
      toast.info("Analyzing CVEs via NVD database...", {
        description: "This may take 30-60 seconds",
        duration: 8000,
      });

      const response = await httpFetch("/api/vulnerabilities/scan", {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(scan),
      });

      const result = await response.json();

      if (result.success) {
        await loadBackendStatus();

        const total = (result.critical_count ?? 0) +
                      (result.high_count ?? 0) +
                      (result.medium_count ?? 0);

        if ((result.critical_count ?? 0) > 0) {
          toast.error(`🚨 ${result.critical_count} CRITICAL vulnerabilities found!`, {
            description: "Immediate patching required per ЗКС чл. 14",
            duration: 10000,
          });
        } else if (total > 0) {
          toast.warning(`${total} vulnerabilities found`, {
            description: `NIS2 Score: ${result.nis2_score}%`,
            duration: 6000,
          });
        } else {
          toast.success("No vulnerabilities detected", {
            description: `NIS2 Score: ${result.nis2_score}% — Compliant`,
            duration: 5000,
          });
        }
      }

    } catch (err: any) {
      toast.error("CVE analysis failed", { description: err.message });
    } finally {
      setAnalyzingCves(false);
    }
  };

  const displayData = backendData?.has_data ? backendData : null;
  const score = displayData?.nis2_score ?? 0;

  // Filter vulnerabilities
  const allVulns = displayData?.vulnerabilities ?? [];
  const filteredVulns = allVulns.filter(v => {
    const matchesSeverity = severityFilter === "all" || v.severity === severityFilter;
    const matchesSearch   = searchQuery === "" ||
      v.software_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.cve_id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  // Software list from local scan
  const softwareList = localScan?.scanned_software ?? [];

  const isLoading = scanning || analyzingCves;

  return (
    <ProtectedRoute>
      <main className="pb-12">

        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                  NIS2 Art. 21(2)(e)
                </span>
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30">
                  ЗКС ЧЛ. 14
                </span>
              </div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                Vulnerability Scanner
              </h1>
              <p className="mt-2 text-muted-foreground">
                CVE detection &amp; patch management per ЗКС (ДВ бр.17 / 13.02.2026)
              </p>
              {lastScan && (
                <p className="text-xs text-muted-foreground mt-1">Last scan: {lastScan}</p>
              )}
              {backendData?.last_scan && !lastScan && (
                <p className="text-xs text-muted-foreground mt-1">
                  Last scan: {new Date(backendData.last_scan).toLocaleString()}
                </p>
              )}
            </div>

            <div className="flex items-center gap-4">
              {/* NIS2 Score */}
              {displayData && (
                <div className="text-right">
                  <div className={`text-5xl font-bold ${getScoreColor(score)}`}>
                    {score}%
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">NIS2 Art. 21(2)(e)</div>
                </div>
              )}

              {/* Scan Button */}
              <button
                onClick={runLocalScan}
                disabled={isLoading}
                className="px-5 py-2.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {scanning
                  ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</>
                  : analyzingCves
                  ? <><Loader2 className="h-4 w-4 animate-spin" />Analyzing CVEs...</>
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

        <div className="section space-y-6">

          {/* No data state */}
          {!displayData && !isLoading && (
            <div className="card-premium p-12 text-center">
              <Bug className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Vulnerability Data</h3>
              <p className="text-sm text-muted-foreground mb-6">
                Run a scan to detect CVE vulnerabilities in installed software
              </p>
              <button
                onClick={runLocalScan}
                disabled={isLoading}
                className="px-6 py-3 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors"
              >
                Run First Scan
              </button>
            </div>
          )}

          {displayData && (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Package className="h-4 w-4 text-blue-400" />
                    <span className="text-xs text-muted-foreground">Software</span>
                  </div>
                  <div className="text-2xl font-bold text-blue-400">
                    {displayData.software_count ?? 0}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">packages</div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <XCircle className="h-4 w-4 text-red-400" />
                    <span className="text-xs text-muted-foreground">Critical</span>
                  </div>
                  <div className="text-2xl font-bold text-red-400">
                    {displayData.critical_count ?? 0}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">CVSS ≥ 9.0</div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-4 w-4 text-orange-400" />
                    <span className="text-xs text-muted-foreground">High</span>
                  </div>
                  <div className="text-2xl font-bold text-orange-400">
                    {displayData.high_count ?? 0}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">CVSS 7.0-8.9</div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-400" />
                    <span className="text-xs text-muted-foreground">Medium</span>
                  </div>
                  <div className="text-2xl font-bold text-yellow-400">
                    {displayData.medium_count ?? 0}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">CVSS 4.0-6.9</div>
                </div>

                <div className="card-premium p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="h-4 w-4 text-blue-400" />
                    <span className="text-xs text-muted-foreground">Low</span>
                  </div>
                  <div className="text-2xl font-bold text-blue-400">
                    {displayData.low_count ?? 0}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">CVSS &lt; 4.0</div>
                </div>
              </div>

              {/* NIS2 Score Bar */}
              <div className="card-premium p-6">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h2 className="text-lg font-semibold">NIS2 Art. 21(2)(e) — Vulnerability Management</h2>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {displayData.zks_article ?? "чл. 14 ЗКС (ДВ бр.17/2026)"} · Host: {displayData.hostname ?? "unknown"}
                    </p>
                  </div>
                  <div className={`text-3xl font-bold ${getScoreColor(score)}`}>{score}%</div>
                </div>
                <div className="h-3 w-full rounded-full bg-muted/30">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${getScoreBg(score)}`}
                    style={{ width: `${score}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-muted-foreground mt-1">
                  <span>0%</span>
                  <span className={`font-bold ${getScoreColor(score)}`}>
                    {displayData.nis2_status?.toUpperCase()}
                  </span>
                  <span>100%</span>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveTab("vulnerabilities")}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === "vulnerabilities"
                      ? "bg-red-500/20 text-red-400 border border-red-500/30"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Bug className="h-4 w-4 inline mr-1" />
                  CVE Vulnerabilities ({allVulns.length})
                </button>
                <button
                  onClick={() => setActiveTab("software")}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === "software"
                      ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Package className="h-4 w-4 inline mr-1" />
                  Software Inventory ({softwareList.length || displayData.software_count || 0})
                </button>
              </div>

              {/* Vulnerabilities Tab */}
              {activeTab === "vulnerabilities" && (
                <div className="card-premium p-6">
                  {/* Filters */}
                  <div className="flex gap-3 mb-4 flex-wrap">
                    <div className="relative flex-1 min-w-48">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <input
                        type="text"
                        placeholder="Search CVE or software..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        className="w-full pl-9 pr-3 py-2 rounded-lg bg-muted/10 border border-border text-sm focus:outline-none focus:border-red-500/50"
                      />
                    </div>
                    <select
                      value={severityFilter}
                      onChange={e => setSeverityFilter(e.target.value)}
                      className="px-3 py-2 rounded-lg bg-muted/10 border border-border text-sm focus:outline-none"
                    >
                      <option value="all">All Severity</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>

                  {filteredVulns.length === 0 ? (
                    <div className="text-center py-12">
                      <CheckCircle className="h-10 w-10 mx-auto text-green-400 mb-3" />
                      <p className="text-sm text-muted-foreground">
                        {allVulns.length === 0
                          ? "No vulnerabilities detected — system is clean"
                          : "No results match your filter"}
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredVulns.map((vuln, i) => (
                        <div
                          key={`${vuln.cve_id}-${i}`}
                          className={`rounded-lg border p-4 cursor-pointer transition-colors ${getSeverityBg(vuln.severity)}`}
                          onClick={() => setExpandedCve(expandedCve === vuln.cve_id ? null : vuln.cve_id)}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-mono font-bold text-sm">
                                  {vuln.cve_id}
                                </span>
                                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${getSeverityBg(vuln.severity)}`}>
                                  {vuln.severity}
                                </span>
                                <span className={`text-sm font-bold ${getCvssColor(vuln.cvss_score)}`}>
                                  CVSS {vuln.cvss_score.toFixed(1)}
                                </span>
                              </div>
                              <div className="text-sm mt-1 opacity-90">
                                {vuln.software_name} {vuln.software_version}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {vuln.patch_available && (
                                <span className="text-xs text-green-400 bg-green-500/10 border border-green-500/20 rounded px-2 py-0.5">
                                  Patch available
                                </span>
                              )}
                              {expandedCve === vuln.cve_id
                                ? <ChevronUp className="h-4 w-4 flex-shrink-0" />
                                : <ChevronDown className="h-4 w-4 flex-shrink-0" />
                              }
                            </div>
                          </div>

                          {expandedCve === vuln.cve_id && (
                            <div className="mt-3 pt-3 border-t border-current/20 space-y-2">
                              <p className="text-xs opacity-80">{vuln.description}</p>
                              <div className="text-xs">
                                <span className="opacity-60">Remediation: </span>
                                <span className="opacity-90">{vuln.remediation}</span>
                              </div>
                              {vuln.published_date && (
                                <div className="text-xs opacity-60">
                                  Published: {vuln.published_date}
                                </div>
                              )}
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline"
                                onClick={e => e.stopPropagation()}
                              >
                                <ExternalLink className="h-3 w-3" />
                                View on NVD
                              </a>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Software Inventory Tab */}
              {activeTab === "software" && (
                <div className="card-premium p-6">
                  {softwareList.length === 0 ? (
                    <div className="text-center py-8">
                      <p className="text-sm text-muted-foreground">
                        Run a scan to populate software inventory
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {softwareList.map((sw, i) => (
                        <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-muted/10 border border-border">
                          <div>
                            <div className="text-sm font-medium">{sw.name}</div>
                            {sw.publisher && (
                              <div className="text-xs text-muted-foreground">{sw.publisher}</div>
                            )}
                          </div>
                          <span className="text-xs text-muted-foreground font-mono">{sw.version}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Recommendations */}
              {(displayData.recommendations?.length ?? 0) > 0 && (
                <div className="card-premium p-6">
                  <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                    Recommendations — ЗКС чл. 14
                  </h2>
                  <div className="space-y-3">
                    {(displayData.recommendations ?? []).map((rec, i) => {
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
                          }`}>{rec}</p>
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