"use client";

import { httpFetch } from "@/lib/api";
import { useState } from "react";
import { Shield, FileText, AlertTriangle, CheckCircle, XCircle, Clock, Download, ChevronRight, Loader2 } from "lucide-react";
import ProtectedRoute from "@/components/ProtectedRoute";

const NIS2_CONTROLS = [
  { id: "logging",            label: "Logging & Monitoring",          score: 92, status: "ok",       article: "Art. 21(2)(g)" },
  { id: "incident_detection", label: "Incident Detection",            score: 95, status: "ok",       article: "Art. 21(2)(a)" },
  { id: "incident_response",  label: "Incident Response",             score: 87, status: "ok",       article: "Art. 21(2)(c)" },
  { id: "vulnerability",      label: "Vulnerability Management",      score: 61, status: "warning",  article: "Art. 21(2)(e)" },
  { id: "patch",              label: "Patch Management",              score: 58, status: "warning",  article: "Art. 21(2)(f)" },
  { id: "backup",             label: "Backup & Recovery",             score: 44, status: "critical", article: "Art. 21(2)(c)" },
  { id: "supply_chain",       label: "Supply Chain Security",         score: 71, status: "ok",       article: "Art. 21(2)(d)" },
  { id: "access_control",     label: "Access Control",                score: 83, status: "ok",       article: "Art. 21(2)(i)" },
];

const REPORTING_PHASES = [
  {
    phase:       "early_warning",
    endpoint:    "/reports/nis2/early-warning",
    deadline:    "24 hours",
    label:       "Early Warning",
    description: "Initial notification to CSIRT/NCA",
    article:     "Art. 23(4)(a)",
  },
  {
    phase:       "incident_notification",
    endpoint:    "/reports/nis2/incident-notification",
    deadline:    "72 hours",
    label:       "Incident Notification",
    description: "Detailed technical report",
    article:     "Art. 23(4)(b)",
  },
  {
    phase:       "final_report",
    endpoint:    "/reports/nis2/final-report",
    deadline:    "1 month",
    label:       "Final Report",
    description: "Root cause & remediation report",
    article:     "Art. 23(4)(c)",
  },
];

type GeneratingState = {
  phase: string;
  format: string;
} | null;

export default function NIS2Page() {
  const [activeTab, setActiveTab]     = useState<"dashboard" | "reporting" | "controls">("dashboard");
  const [generating, setGenerating]   = useState<GeneratingState>(null);
  const [error, setError]             = useState<string | null>(null);

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    "Authorization": `Bearer ${localStorage.getItem("access_token") || ""}`,
  });

  const overallScore = Math.round(
    NIS2_CONTROLS.reduce((sum, c) => sum + c.score, 0) / NIS2_CONTROLS.length
  );


  const handleGenerateReport = async (
    endpoint: string,
    phase: string,
    format: "pdf" | "csirt" | "enisa" = "pdf"
  ) => {
    setGenerating({ phase, format });
    setError(null);

    try {
      const response = await httpFetch(`/api${endpoint}`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ export_format: format }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || `Server error ${response.status}`);
      }

      // Determine filename and mime type from response headers
      const disposition  = response.headers.get("Content-Disposition") || "";
      const filenameMatch = disposition.match(/filename=(.+)/);
      const filename     = filenameMatch ? filenameMatch[1] : `NIS2_${phase}_${Date.now()}.${format === "pdf" ? "pdf" : "json"}`;
      const mimeType     = format === "pdf" ? "application/pdf" : "application/json";

      const blob = await response.blob();
      const url  = window.URL.createObjectURL(new Blob([blob], { type: mimeType }));
      const a    = document.createElement("a");
      a.href     = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

    } catch (err: any) {
      setError(err.message || "Failed to generate report");
    } finally {
      setGenerating(null);
    }
  };

  const isGenerating = (phase: string, format: string) =>
    generating?.phase === phase && generating?.format === format;

  const anyGenerating = generating !== null;

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
    if (status === "ok")       return <CheckCircle className="h-4 w-4 text-green-400" />;
    if (status === "warning")  return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
    return <XCircle className="h-4 w-4 text-red-400" />;
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
                  EU NIS2 DIRECTIVE 2022/2555
                </span>
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-500/20 text-green-400 border border-green-500/30">
                  BG State Gazette No.17 / 13.02.2026
                </span>
              </div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                NIS2 Compliance Center
              </h1>
              <p className="mt-2 text-muted-foreground">
                Network &amp; Information Security Directive — Compliance monitoring &amp; incident reporting
              </p>
            </div>
            <div className="text-right">
              <div className={`text-5xl font-bold ${getScoreColor(overallScore)}`}>
                {overallScore}%
              </div>
              <div className="text-sm text-muted-foreground mt-1">Overall Compliance Score</div>
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

        {/* Tabs */}
        <div className="page-container mt-6">
          <div className="flex gap-2 border-b border-border">
            {[
              { id: "dashboard",  label: "Dashboard" },
              { id: "reporting",  label: "Incident Reporting" },
              { id: "controls",   label: "Security Controls" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? "border-purple-500 text-purple-400"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── DASHBOARD TAB ─────────────────────────────────────────── */}
        {activeTab === "dashboard" && (
          <div className="section space-y-6">

            {/* Score Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Controls Passed</div>
                <div className="text-2xl font-bold text-green-400">
                  {NIS2_CONTROLS.filter(c => c.status === "ok").length}/{NIS2_CONTROLS.length}
                </div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Warnings</div>
                <div className="text-2xl font-bold text-yellow-400">
                  {NIS2_CONTROLS.filter(c => c.status === "warning").length}
                </div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Critical Gaps</div>
                <div className="text-2xl font-bold text-red-400">
                  {NIS2_CONTROLS.filter(c => c.status === "critical").length}
                </div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Max Fine Exposure</div>
                <div className="text-2xl font-bold text-orange-400">€10M</div>
              </div>
            </div>

            {/* Controls Overview */}
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-purple-500" />
                NIS2 Article 21 — Security Controls
              </h2>
              <div className="space-y-3">
                {NIS2_CONTROLS.map((control) => (
                  <div key={control.id} className="flex items-center gap-4">
                    {getStatusIcon(control.status)}
                    <div className="flex-1">
                      <div className="flex justify-between text-sm mb-1">
                        <span className="font-medium">{control.label}</span>
                        <span className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{control.article}</span>
                          <span className={`font-bold ${getScoreColor(control.score)}`}>{control.score}%</span>
                        </span>
                      </div>
                      <div className="h-1.5 w-full rounded-full bg-muted/30">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${getScoreBg(control.score)}`}
                          style={{ width: `${control.score}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Report Generation */}
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <FileText className="h-5 w-5 text-blue-500" />
                Quick Report Generation
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {REPORTING_PHASES.map((item) => (
                  <button
                    key={item.phase}
                    onClick={() => handleGenerateReport(item.endpoint, item.phase, "pdf")}
                    disabled={anyGenerating}
                    className="p-4 rounded-lg border border-border hover:border-purple-500/50 hover:bg-purple-500/5 transition-all text-left group disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <Clock className="h-5 w-5 text-purple-400" />
                      <span className="text-xs font-bold text-purple-400">{item.deadline}</span>
                    </div>
                    <div className="font-semibold text-sm mb-1">{item.label}</div>
                    <div className="text-xs text-muted-foreground mb-1">{item.description}</div>
                    <div className="text-xs text-muted-foreground mb-3">{item.article}</div>
                    <div className="flex items-center gap-1 text-xs text-purple-400 group-hover:gap-2 transition-all">
                      {isGenerating(item.phase, "pdf") ? (
                        <><Loader2 className="h-3 w-3 animate-spin" /><span>Generating...</span></>
                      ) : (
                        <><Download className="h-3 w-3" /><span>Generate PDF</span><ChevronRight className="h-3 w-3" /></>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── REPORTING TAB ─────────────────────────────────────────── */}
        {activeTab === "reporting" && (
          <div className="section space-y-6">
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-2">NIS2 Incident Reporting Timeline</h2>
              <p className="text-sm text-muted-foreground mb-6">
                Mandatory process under NIS2 Article 23 — upon detection of a significant incident
              </p>
              <div className="space-y-6">
                {REPORTING_PHASES.map((item, index) => (
                  <div key={item.phase} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="h-8 w-8 rounded-full bg-purple-500/20 border border-purple-500/50 flex items-center justify-center text-purple-400 font-bold text-sm">
                        {index + 1}
                      </div>
                      {index < REPORTING_PHASES.length - 1 && (
                        <div className="w-0.5 h-10 bg-border mt-1" />
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <div className="flex items-center gap-3 mb-1">
                        <span className="font-semibold">{item.label}</span>
                        <span className="px-2 py-0.5 rounded-full text-xs bg-purple-500/20 text-purple-400 border border-purple-500/30">
                          {item.deadline}
                        </span>
                        <span className="text-xs text-muted-foreground">{item.article}</span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-3">{item.description}</p>
                      <div className="flex flex-wrap gap-2">

                        {/* PDF */}
                        <button
                          onClick={() => handleGenerateReport(item.endpoint, item.phase, "pdf")}
                          disabled={anyGenerating}
                          className="px-3 py-1.5 rounded text-xs bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                          {isGenerating(item.phase, "pdf")
                            ? <><Loader2 className="h-3 w-3 animate-spin" />Generating...</>
                            : <><Download className="h-3 w-3" />PDF Report</>
                          }
                        </button>

                        {/* CSIRT */}
                        <button
                          onClick={() => handleGenerateReport(item.endpoint, item.phase, "csirt")}
                          disabled={anyGenerating}
                          className="px-3 py-1.5 rounded text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 hover:bg-blue-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                          {isGenerating(item.phase, "csirt")
                            ? <><Loader2 className="h-3 w-3 animate-spin" />Generating...</>
                            : <><Download className="h-3 w-3" />CSIRT Bulgaria</>
                          }
                        </button>

                        {/* ENISA */}
                        <button
                          onClick={() => handleGenerateReport(item.endpoint, item.phase, "enisa")}
                          disabled={anyGenerating}
                          className="px-3 py-1.5 rounded text-xs bg-green-500/10 text-green-400 border border-green-500/30 hover:bg-green-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                          {isGenerating(item.phase, "enisa")
                            ? <><Loader2 className="h-3 w-3 animate-spin" />Generating...</>
                            : <><Download className="h-3 w-3" />ENISA Format</>
                          }
                        </button>

                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── CONTROLS TAB ──────────────────────────────────────────── */}
        {activeTab === "controls" && (
          <div className="section space-y-4">
            {NIS2_CONTROLS.map((control) => (
              <div key={control.id} className="bg-card border border-border rounded-lg p-5">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(control.status)}
                    <div>
                      <div className="font-semibold">{control.label}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">{control.article}</div>
                    </div>
                  </div>
                  <div className={`text-2xl font-bold ${getScoreColor(control.score)}`}>
                    {control.score}%
                  </div>
                </div>
                <div className="mt-3 h-2 w-full rounded-full bg-muted/30">
                  <div
                    className={`h-full rounded-full ${getScoreBg(control.score)}`}
                    style={{ width: `${control.score}%` }}
                  />
                </div>
                {control.status !== "ok" && (
                  <div className="mt-3 p-3 rounded bg-yellow-500/5 border border-yellow-500/20">
                    <p className="text-xs text-yellow-400">
                      ⚠ Action required — This control needs improvement to meet NIS2 requirements
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

      </main>
    </ProtectedRoute>
  );
}