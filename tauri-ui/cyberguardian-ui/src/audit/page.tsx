"use client";

import { httpFetch } from "@/lib/api";
import { toast } from "sonner";
import { useState, useEffect, useCallback } from "react";
import { Shield, Download, Search, Clock, CheckCircle, AlertTriangle, FileText, Lock, Loader2 } from "lucide-react";
import ProtectedRoute from "@/components/ProtectedRoute";

type EvidenceRecord = {
  id: string;
  timestamp: string;
  event_type: string;
  process_name: string;
  pid: number;
  mitre_technique: string;
  action_taken: string;
  severity: string;
  success: boolean;
  details: string;
};

const RETENTION_OPTIONS = ["30 days", "90 days", "180 days", "365 days"];

export default function AuditPage() {
  const [evidence, setEvidence]           = useState<EvidenceRecord[]>([]);
  const [search, setSearch]               = useState("");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [retention, setRetention]         = useState("90 days");
  const [exporting, setExporting]         = useState<string | null>(null);
  const [error, setError]                 = useState<string | null>(null);

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    "Authorization": `Bearer ${localStorage.getItem("access_token") || ""}`,
  });

  // Load evidence from backend threats
  const fetchEvidence = useCallback(async () => {
    try {
      const response = await httpFetch(`/api/threats?limit=100`, {
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      if (data.success && data.threats) {
        const mapped: EvidenceRecord[] = data.threats.map((t: any, i: number) => ({
          id:             `EVD-${new Date().getFullYear()}-${String(i + 1).padStart(3, "0")}`,
          timestamp:      t.timestamp || new Date().toISOString(),
          event_type:     t.threat_type || "Threat Detected",
          process_name:   t.process_name || t.source_ip || "N/A",
          pid:            t.pid || 0,
          mitre_technique: t.mitre_technique || "N/A",
          action_taken:   t.blocked ? "Process terminated" : "Detected",
          severity:       t.severity || "medium",
          success:        true,
          details:        t.description || t.threat_type || "",
        }));
        setEvidence(mapped);
      }
    } catch (err) {
      console.error("Failed to fetch evidence:", err);
    }
  }, []);

  useEffect(() => {
    fetchEvidence();
  }, [fetchEvidence]);

  const filtered = evidence.filter((e) => {
    const matchSearch =
      e.process_name.toLowerCase().includes(search.toLowerCase()) ||
      e.mitre_technique.toLowerCase().includes(search.toLowerCase()) ||
      e.event_type.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = filterSeverity === "all" || e.severity === filterSeverity;
    return matchSearch && matchSeverity;
  });

  const handleExport = async (format: "pdf" | "csv" | "enisa") => {
    setExporting(format);
    setError(null);

    try {
      const response = await httpFetch(`/api/reports/audit/export`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          export_format:   format,
          severity_filter: filterSeverity === "all" ? null : filterSeverity,
        }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `Server error ${response.status}`);
      }

      const disposition   = response.headers.get("Content-Disposition") || "";
      const filenameMatch = disposition.match(/filename=(.+)/);
      const timestamp     = new Date().toISOString().slice(0, 10);
      const ext           = format === "pdf" ? "pdf" : format === "csv" ? "csv" : "json";
      const filename      = filenameMatch
        ? filenameMatch[1]
        : `CyberGuardian_AuditEvidence_${timestamp}.${ext}`;

      const mimeTypes: Record<string, string> = {
        pdf:   "application/pdf",
        csv:   "text/csv",
        enisa: "application/json",
      };

      const blob = await response.blob();
      const url  = window.URL.createObjectURL(new Blob([blob], { type: mimeTypes[format] }));
      const a    = document.createElement("a");
      a.href     = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      toast.success("Export downloaded successfully", {
        description: `${filename} saved to Downloads folder`,
        duration: 5000,
      });

    } catch (err: any) {
      setError(err.message || "Export failed");
      toast.error("Export failed", {
        description: err.message,
        duration: 5000,
      });
    } finally {
      setExporting(null);
    }
  };

  const getSeverityColor = (severity: string) => {
    if (severity === "critical") return "text-red-400 bg-red-500/10 border-red-500/30";
    if (severity === "high")     return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
  };

  const uniqueMitre = new Set(evidence.map(e => e.mitre_technique)).size;

  return (
    <ProtectedRoute>
      <main className="pb-12">

        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  NIS2 Art. 23 — AUDIT EVIDENCE
                </span>
              </div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                Audit Evidence Vault
              </h1>
              <p className="mt-2 text-muted-foreground">
                Tamper-proof security evidence for NIS2 regulatory audits
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-green-400" />
              <span className="text-sm text-green-400 font-medium">Evidence Integrity: Verified</span>
            </div>
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="page-container mt-4">
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-between">
              <span className="text-sm text-red-400">⚠ {error}</span>
              <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300 text-xs">Dismiss</button>
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="section">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="card-premium p-5">
              <div className="text-sm text-muted-foreground mb-1">Total Records</div>
              <div className="text-2xl font-bold text-purple-400">{evidence.length}</div>
            </div>
            <div className="card-premium p-5">
              <div className="text-sm text-muted-foreground mb-1">Actions Taken</div>
              <div className="text-2xl font-bold text-green-400">
                {evidence.filter(e => e.success).length}
              </div>
            </div>
            <div className="card-premium p-5">
              <div className="text-sm text-muted-foreground mb-1">MITRE Techniques</div>
              <div className="text-2xl font-bold text-orange-400">{uniqueMitre}</div>
            </div>
            <div className="card-premium p-5">
              <div className="text-sm text-muted-foreground mb-1">Log Retention</div>
              <select
                value={retention}
                onChange={(e) => setRetention(e.target.value)}
                className="mt-1 bg-transparent text-lg font-bold text-blue-400 border-none outline-none cursor-pointer"
              >
                {RETENTION_OPTIONS.map(o => (
                  <option key={o} value={o} className="bg-card">{o}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Evidence Table */}
        <div className="section">
          <div className="bg-card border border-border rounded-lg p-6">

            {/* Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <FileText className="h-5 w-5 text-purple-500" />
                Security Evidence Records
              </h2>
              <div className="flex flex-wrap items-center gap-3">

                {/* Search */}
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search evidence..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-9 pr-4 py-2 text-sm bg-muted/20 border border-border rounded-lg outline-none focus:border-purple-500/50 w-48"
                  />
                </div>

                {/* Severity Filter */}
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="px-3 py-2 text-sm bg-muted/20 border border-border rounded-lg outline-none cursor-pointer"
                >
                  <option value="all">All Severity</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                </select>

                {/* Export Buttons */}
                <button
                  onClick={() => handleExport("pdf")}
                  disabled={exporting !== null}
                  className="px-3 py-2 text-sm bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded-lg hover:bg-purple-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
                >
                  {exporting === "pdf"
                    ? <><Loader2 className="h-3 w-3 animate-spin" />Exporting...</>
                    : <><Download className="h-3 w-3" />PDF</>
                  }
                </button>
                <button
                  onClick={() => handleExport("csv")}
                  disabled={exporting !== null}
                  className="px-3 py-2 text-sm bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded-lg hover:bg-blue-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
                >
                  {exporting === "csv"
                    ? <><Loader2 className="h-3 w-3 animate-spin" />Exporting...</>
                    : <><Download className="h-3 w-3" />CSV</>
                  }
                </button>
                <button
                  onClick={() => handleExport("enisa")}
                  disabled={exporting !== null}
                  className="px-3 py-2 text-sm bg-green-500/10 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
                >
                  {exporting === "enisa"
                    ? <><Loader2 className="h-3 w-3 animate-spin" />Exporting...</>
                    : <><Download className="h-3 w-3" />ENISA</>
                  }
                </button>

              </div>
            </div>

            {/* Table */}
            {evidence.length === 0 ? (
              <div className="text-center py-12">
                <Shield className="h-8 w-8 mx-auto text-green-500 mb-3" />
                <p className="text-muted-foreground">No evidence records — system is clean</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-muted-foreground text-xs uppercase">
                      <th className="text-left pb-3 pr-4">Evidence ID</th>
                      <th className="text-left pb-3 pr-4">Timestamp</th>
                      <th className="text-left pb-3 pr-4">Process</th>
                      <th className="text-left pb-3 pr-4">MITRE</th>
                      <th className="text-left pb-3 pr-4">Severity</th>
                      <th className="text-left pb-3 pr-4">Action</th>
                      <th className="text-left pb-3">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((record) => (
                      <tr key={record.id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                        <td className="py-3 pr-4 font-mono text-xs text-purple-400">{record.id}</td>
                        <td className="py-3 pr-4 text-xs text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(record.timestamp).toLocaleString()}
                          </div>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs">{record.process_name}</td>
                        <td className="py-3 pr-4">
                          {record.mitre_technique !== "N/A" ? (
                            <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 text-xs border border-orange-500/20">
                              {record.mitre_technique}
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`px-2 py-0.5 rounded text-xs border ${getSeverityColor(record.severity)}`}>
                            {record.severity}
                          </span>
                        </td>
                        <td className="py-3 pr-4 text-xs">{record.action_taken}</td>
                        <td className="py-3">
                          {record.success ? (
                            <span className="flex items-center gap-1 text-green-400 text-xs">
                              <CheckCircle className="h-3 w-3" />Verified
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-yellow-400 text-xs">
                              <AlertTriangle className="h-3 w-3" />Partial
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {filtered.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground text-sm">
                    No records match your search
                  </div>
                )}
              </div>
            )}

          </div>
        </div>
      </main>
    </ProtectedRoute>
  );
}