"use client";

import { useState, useEffect, useCallback } from "react";
import { Shield, Download, Search, Filter, Clock, CheckCircle, AlertTriangle, FileText, Lock } from "lucide-react";
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

const MOCK_EVIDENCE: EvidenceRecord[] = [
  {
    id: "EVD-2026-001",
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    event_type: "Process Blocked",
    process_name: "mimikatz.exe",
    pid: 4521,
    mitre_technique: "T1003",
    action_taken: "Process terminated",
    severity: "critical",
    success: true,
    details: "Credential dumping tool detected and blocked",
  },
  {
    id: "EVD-2026-002",
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    event_type: "Process Blocked",
    process_name: "powershell.exe",
    pid: 8832,
    mitre_technique: "T1059.001",
    action_taken: "Process terminated",
    severity: "critical",
    success: true,
    details: "Malicious PowerShell with encoded command blocked",
  },
  {
    id: "EVD-2026-003",
    timestamp: new Date(Date.now() - 10800000).toISOString(),
    event_type: "Process Blocked",
    process_name: "mshta.exe",
    pid: 6123,
    mitre_technique: "T1218.005",
    action_taken: "Process terminated",
    severity: "critical",
    success: true,
    details: "LOLBin execution blocked",
  },
  {
    id: "EVD-2026-004",
    timestamp: new Date(Date.now() - 14400000).toISOString(),
    event_type: "Process Blocked",
    process_name: "vssadmin.exe",
    pid: 9241,
    mitre_technique: "T1490",
    action_taken: "Process terminated",
    severity: "critical",
    success: true,
    details: "Shadow copy deletion attempt blocked",
  },
  {
    id: "EVD-2026-005",
    timestamp: new Date(Date.now() - 18000000).toISOString(),
    event_type: "Process Blocked",
    process_name: "schtasks.exe",
    pid: 7734,
    mitre_technique: "T1053.005",
    action_taken: "Process terminated",
    severity: "high",
    success: true,
    details: "Malicious scheduled task creation blocked",
  },
];

const RETENTION_OPTIONS = ["30 days", "90 days", "180 days", "365 days"];

export default function AuditPage() {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>(MOCK_EVIDENCE);
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [retention, setRetention] = useState("90 days");
  const [exporting, setExporting] = useState(false);

  const filtered = evidence.filter((e) => {
    const matchSearch =
      e.process_name.toLowerCase().includes(search.toLowerCase()) ||
      e.mitre_technique.toLowerCase().includes(search.toLowerCase()) ||
      e.event_type.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = filterSeverity === "all" || e.severity === filterSeverity;
    return matchSearch && matchSeverity;
  });

  const handleExport = (format: string) => {
    setExporting(true);
    setTimeout(() => setExporting(false), 1500);
  };

  const getSeverityColor = (severity: string) => {
    if (severity === "critical") return "text-red-400 bg-red-500/10 border-red-500/30";
    if (severity === "high") return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
  };

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
              <div className="text-2xl font-bold text-orange-400">
                {new Set(evidence.map(e => e.mitre_technique)).size}
              </div>
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

        {/* Controls */}
        <div className="section">
          <div className="bg-card border border-border rounded-lg p-6">
            {/* Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <FileText className="h-5 w-5 text-purple-500" />
                Security Evidence Records
              </h2>
              <div className="flex items-center gap-3">
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
                {/* Filter */}
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
                {/* Export */}
                <div className="flex gap-2">
                  <button
                    onClick={() => handleExport("pdf")}
                    className="px-3 py-2 text-sm bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded-lg hover:bg-purple-500/20 transition-colors flex items-center gap-1"
                  >
                    <Download className="h-3 w-3" />
                    {exporting ? "Exporting..." : "PDF"}
                  </button>
                  <button
                    onClick={() => handleExport("csv")}
                    className="px-3 py-2 text-sm bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded-lg hover:bg-blue-500/20 transition-colors flex items-center gap-1"
                  >
                    <Download className="h-3 w-3" />
                    CSV
                  </button>
                  <button
                    onClick={() => handleExport("enisa")}
                    className="px-3 py-2 text-sm bg-green-500/10 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/20 transition-colors flex items-center gap-1"
                  >
                    <Download className="h-3 w-3" />
                    ENISA
                  </button>
                </div>
              </div>
            </div>

            {/* Table */}
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
                <tbody className="space-y-2">
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
                        <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 text-xs border border-orange-500/20">
                          {record.mitre_technique}
                        </span>
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
                            <CheckCircle className="h-3 w-3" />
                            Verified
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-yellow-400 text-xs">
                            <AlertTriangle className="h-3 w-3" />
                            Partial
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {filtered.length === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                No evidence records match your search
              </div>
            )}
          </div>
        </div>
      </main>
    </ProtectedRoute>
  );
}