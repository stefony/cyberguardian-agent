"use client";

import { useState } from "react";
import { Shield, FileText, AlertTriangle, CheckCircle, XCircle, Clock, Download, ChevronRight } from "lucide-react";
import ProtectedRoute from "@/components/ProtectedRoute";

const NIS2_CONTROLS = [
  { id: "logging", label: "Logging & Monitoring", score: 92, status: "ok", article: "Art. 21(2)(g)" },
  { id: "incident_detection", label: "Incident Detection", score: 95, status: "ok", article: "Art. 21(2)(a)" },
  { id: "incident_response", label: "Incident Response", score: 87, status: "ok", article: "Art. 21(2)(c)" },
  { id: "vulnerability", label: "Vulnerability Management", score: 61, status: "warning", article: "Art. 21(2)(e)" },
  { id: "patch", label: "Patch Management", score: 58, status: "warning", article: "Art. 21(2)(e)" },
  { id: "backup", label: "Backup & Recovery", score: 44, status: "critical", article: "Art. 21(2)(c)" },
  { id: "supply_chain", label: "Supply Chain Security", score: 71, status: "ok", article: "Art. 21(2)(d)" },
  { id: "access_control", label: "Access Control", score: 83, status: "ok", article: "Art. 21(2)(i)" },
];

const REPORTING_TIMELINE = [
  { phase: "Early Warning", deadline: "24 hours", description: "Initial notification to CSIRT/NCA", status: "ready" },
  { phase: "Incident Notification", deadline: "72 hours", description: "Detailed technical report", status: "ready" },
  { phase: "Final Report", deadline: "1 month", description: "Root cause & remediation report", status: "ready" },
];

export default function NIS2Page() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "reporting" | "controls">("dashboard");
  const [generatingReport, setGeneratingReport] = useState<string | null>(null);

  const overallScore = Math.round(
    NIS2_CONTROLS.reduce((sum, c) => sum + c.score, 0) / NIS2_CONTROLS.length
  );

  const handleGenerateReport = (type: string) => {
    setGeneratingReport(type);
    setTimeout(() => setGeneratingReport(null), 2000);
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

  const getStatusIcon = (status: string) => {
    if (status === "ok") return <CheckCircle className="h-4 w-4 text-green-400" />;
    if (status === "warning") return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
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
                  ДВ бр.17 / 13.02.2026
                </span>
              </div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                NIS2 Compliance Center
              </h1>
              <p className="mt-2 text-muted-foreground">
                Network & Information Security Directive — Compliance monitoring & incident reporting
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

        {/* Tabs */}
        <div className="page-container mt-6">
          <div className="flex gap-2 border-b border-border">
            {[
              { id: "dashboard", label: "Dashboard" },
              { id: "reporting", label: "Incident Reporting" },
              { id: "controls", label: "Security Controls" },
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

        {/* Dashboard Tab */}
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

            {/* Quick Actions */}
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <FileText className="h-5 w-5 text-blue-500" />
                Quick Report Generation
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {REPORTING_TIMELINE.map((item) => (
                  <button
                    key={item.phase}
                    onClick={() => handleGenerateReport(item.phase)}
                    className="p-4 rounded-lg border border-border hover:border-purple-500/50 hover:bg-purple-500/5 transition-all text-left group"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <Clock className="h-5 w-5 text-purple-400" />
                      <span className="text-xs font-bold text-purple-400">{item.deadline}</span>
                    </div>
                    <div className="font-semibold text-sm mb-1">{item.phase}</div>
                    <div className="text-xs text-muted-foreground mb-3">{item.description}</div>
                    <div className="flex items-center gap-1 text-xs text-purple-400 group-hover:gap-2 transition-all">
                      {generatingReport === item.phase ? (
                        <span>Generating...</span>
                      ) : (
                        <>
                          <Download className="h-3 w-3" />
                          <span>Generate Report</span>
                          <ChevronRight className="h-3 w-3" />
                        </>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Reporting Tab */}
        {activeTab === "reporting" && (
          <div className="section space-y-6">
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-2">NIS2 Incident Reporting Timeline</h2>
              <p className="text-sm text-muted-foreground mb-6">
                Задължителен процес по чл. 23 от Директива NIS2 — при значителен инцидент
              </p>
              <div className="space-y-4">
                {REPORTING_TIMELINE.map((item, index) => (
                  <div key={item.phase} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="h-8 w-8 rounded-full bg-purple-500/20 border border-purple-500/50 flex items-center justify-center text-purple-400 font-bold text-sm">
                        {index + 1}
                      </div>
                      {index < REPORTING_TIMELINE.length - 1 && (
                        <div className="w-0.5 h-8 bg-border mt-1" />
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <div className="flex items-center gap-3 mb-1">
                        <span className="font-semibold">{item.phase}</span>
                        <span className="px-2 py-0.5 rounded-full text-xs bg-purple-500/20 text-purple-400 border border-purple-500/30">
                          {item.deadline}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-3">{item.description}</p>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleGenerateReport(`${item.phase}-pdf`)}
                          className="px-3 py-1.5 rounded text-xs bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors flex items-center gap-1"
                        >
                          <Download className="h-3 w-3" />
                          PDF Report
                        </button>
                        <button
                          onClick={() => handleGenerateReport(`${item.phase}-csirt`)}
                          className="px-3 py-1.5 rounded text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 hover:bg-blue-500/20 transition-colors flex items-center gap-1"
                        >
                          <Download className="h-3 w-3" />
                          CSIRT Bulgaria
                        </button>
                        <button
                          onClick={() => handleGenerateReport(`${item.phase}-enisa`)}
                          className="px-3 py-1.5 rounded text-xs bg-green-500/10 text-green-400 border border-green-500/30 hover:bg-green-500/20 transition-colors flex items-center gap-1"
                        >
                          <Download className="h-3 w-3" />
                          ENISA Format
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Controls Tab */}
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
                      ⚠️ Action required — This control needs improvement to meet NIS2 requirements
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