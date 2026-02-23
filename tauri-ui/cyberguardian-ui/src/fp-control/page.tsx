"use client";

import { useState, useEffect, useCallback } from "react";
import { FilterX, Shield, Plus, Trash2, RefreshCw, CheckCircle } from "lucide-react";
import ProtectedRoute from "@/components/ProtectedRoute";

const API_URL = import.meta.env.VITE_API_URL || "";
const getHeaders = () => ({
  Authorization: `Bearer ${localStorage.getItem("access_token")}`,
  "Content-Type": "application/json",
});

export default function FPControlPage() {
  const [rules, setRules] = useState<any[]>([]);
  const [trusted, setTrusted] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  // New rule form
  const [newProcess, setNewProcess] = useState("");
  const [newParent, setNewParent] = useState("");
  const [newReason, setNewReason] = useState("");

  // New trusted form
  const [newTrustedName, setNewTrustedName] = useState("");
  const [newTrustedHash, setNewTrustedHash] = useState("");
  const [newTrustedReason, setNewTrustedReason] = useState("");

  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const showMessage = (text: string, type: "success" | "error") => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 3000);
  };

  const fetchAll = useCallback(async () => {
    try {
      const [rulesRes, trustedRes, statsRes] = await Promise.all([
        fetch(`${API_URL}/api/correlation/suppression/rules`, { headers: getHeaders() }),
        fetch(`${API_URL}/api/correlation/trusted`, { headers: getHeaders() }),
        fetch(`${API_URL}/api/correlation/stats`, { headers: getHeaders() }),
      ]);
      const rulesData = await rulesRes.json();
      const trustedData = await trustedRes.json();
      const statsData = await statsRes.json();

      if (rulesData.success) setRules(rulesData.rules || []);
      if (trustedData.success) setTrusted(trustedData.processes || []);
      if (statsData.success) setStats(statsData.statistics);
    } catch (err) {
      console.error("Error fetching FP data:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const addSuppressionRule = async () => {
    if (!newProcess || !newParent) return showMessage("Process and Parent are required", "error");
    try {
      const res = await fetch(`${API_URL}/api/correlation/suppression/add`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({ process: newProcess, parent: newParent, reason: newReason }),
      });
      const data = await res.json();
      if (data.success) {
        showMessage("Suppression rule added ✓", "success");
        setNewProcess(""); setNewParent(""); setNewReason("");
        fetchAll();
      }
    } catch (err) {
      showMessage("Error adding rule", "error");
    }
  };

  const addTrustedProcess = async () => {
    if (!newTrustedName) return showMessage("Process name is required", "error");
    try {
      const res = await fetch(`${API_URL}/api/correlation/trusted/add`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({ name: newTrustedName, hash: newTrustedHash, reason: newTrustedReason }),
      });
      const data = await res.json();
      if (data.success) {
        showMessage("Trusted process added ✓", "success");
        setNewTrustedName(""); setNewTrustedHash(""); setNewTrustedReason("");
        fetchAll();
      }
    } catch (err) {
      showMessage("Error adding trusted process", "error");
    }
  };

  return (
    <ProtectedRoute>
      <main className="pb-12">
        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              FP Control Layer
            </h1>
            <p className="mt-2 text-muted-foreground">
              False Positive suppression — enterprise-grade alert accuracy
            </p>
          </div>
        </div>

        {/* Notification */}
        {message && (
          <div className={`mx-6 mb-4 px-4 py-3 rounded-lg text-sm font-medium ${
            message.type === "success"
              ? "bg-green-500/10 text-green-400 border border-green-500/20"
              : "bg-red-500/10 text-red-400 border border-red-500/20"
          }`}>
            {message.text}
          </div>
        )}

        {/* Stats */}
        {stats && (
          <div className="section">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Suppression Rules</div>
                <div className="text-2xl font-bold text-green-400">{stats.suppression_rules ?? rules.length}</div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Trusted Processes</div>
                <div className="text-2xl font-bold text-blue-400">{stats.trusted_processes ?? trusted.length}</div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Auto-Suppressed</div>
                <div className="text-2xl font-bold text-gray-400">{stats.suppressed_count ?? 0}</div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Active Incidents</div>
                <div className="text-2xl font-bold text-purple-400">{stats.active_incidents ?? 0}</div>
              </div>
            </div>
          </div>
        )}

        <div className="section grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Suppression Rules */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <FilterX className="h-5 w-5 text-green-500" />
              Suppression Rules
            </h2>

            {/* Add Rule Form */}
            <div className="space-y-3 mb-6 p-4 bg-muted/10 rounded-lg border border-border">
              <div className="text-sm font-medium text-muted-foreground">Add New Rule</div>
              <input
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                placeholder="Process (e.g. powershell.exe)"
                value={newProcess}
                onChange={(e) => setNewProcess(e.target.value)}
              />
              <input
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                placeholder="Parent (e.g. vscode.exe)"
                value={newParent}
                onChange={(e) => setNewParent(e.target.value)}
              />
              <input
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                placeholder="Reason (e.g. IDE terminal)"
                value={newReason}
                onChange={(e) => setNewReason(e.target.value)}
              />
              <button
                onClick={addSuppressionRule}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded bg-green-600 hover:bg-green-700 text-white text-sm font-medium transition-colors"
              >
                <Plus className="h-4 w-4" /> Add Rule
              </button>
            </div>

            {/* Rules List */}
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {rules.map((rule, i) => (
                <div key={i} className="flex items-start justify-between p-3 rounded bg-muted/10 border border-border text-sm">
                  <div>
                    <div className="font-mono text-green-400">{rule.process} ← {rule.parent}</div>
                    <div className="text-muted-foreground text-xs mt-1">{rule.reason}</div>
                  </div>
                  <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0 mt-0.5" />
                </div>
              ))}
              {rules.length === 0 && (
                <p className="text-center text-muted-foreground text-sm py-4">No rules yet</p>
              )}
            </div>
          </div>

          {/* Trusted Processes */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-500" />
              Trusted Processes
            </h2>

            {/* Add Trusted Form */}
            <div className="space-y-3 mb-6 p-4 bg-muted/10 rounded-lg border border-border">
              <div className="text-sm font-medium text-muted-foreground">Add Trusted Process</div>
              <input
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                placeholder="Process name (e.g. MsMpEng.exe)"
                value={newTrustedName}
                onChange={(e) => setNewTrustedName(e.target.value)}
              />
              <input
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                placeholder="SHA256 hash (optional)"
                value={newTrustedHash}
                onChange={(e) => setNewTrustedHash(e.target.value)}
              />
              <input
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                placeholder="Reason (e.g. Windows Defender)"
                value={newTrustedReason}
                onChange={(e) => setNewTrustedReason(e.target.value)}
              />
              <button
                onClick={addTrustedProcess}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors"
              >
                <Plus className="h-4 w-4" /> Add Trusted
              </button>
            </div>

            {/* Trusted List */}
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {trusted.map((proc, i) => (
                <div key={i} className="flex items-start justify-between p-3 rounded bg-muted/10 border border-border text-sm">
                  <div>
                    <div className="font-mono text-blue-400">{proc.name}</div>
                    <div className="text-muted-foreground text-xs mt-1">{proc.reason}</div>
                    {proc.hash && (
                      <div className="text-muted-foreground text-xs font-mono truncate max-w-48">{proc.hash}</div>
                    )}
                  </div>
                  <Shield className="h-4 w-4 text-blue-500 flex-shrink-0 mt-0.5" />
                </div>
              ))}
              {trusted.length === 0 && (
                <p className="text-center text-muted-foreground text-sm py-4">No trusted processes yet</p>
              )}
            </div>
          </div>
        </div>

        {/* How it works */}
        <div className="section">
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-4">How FP Control Works</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="p-4 rounded bg-muted/10 border border-border">
                <div className="text-green-400 font-semibold mb-2">🟢 FP Score 70-100</div>
                <div className="text-muted-foreground">Auto-suppressed. Event matches known safe pattern. No alert generated.</div>
              </div>
              <div className="p-4 rounded bg-muted/10 border border-border">
                <div className="text-yellow-400 font-semibold mb-2">🟡 FP Score 50-69</div>
                <div className="text-muted-foreground">Response level reduced by one step. Alert generated but downgraded.</div>
              </div>
              <div className="p-4 rounded bg-muted/10 border border-border">
                <div className="text-red-400 font-semibold mb-2">🔴 FP Score 0-29</div>
                <div className="text-muted-foreground">Real threat. Full response level applied. Immediate action required.</div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </ProtectedRoute>
  );
}