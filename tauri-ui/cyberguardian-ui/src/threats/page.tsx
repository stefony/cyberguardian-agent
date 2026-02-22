"use client";
import { httpFetch } from "@/lib/api";
import { Shield, AlertTriangle, TrendingUp, Filter, RefreshCw, Ban, X, Copy, CheckCircle2 } from "lucide-react";
import { threatsApi } from "@/lib/api";
import type { ThreatResponse, ThreatStats } from "@/lib/types";
import { useWebSocketContext } from "@/lib/contexts/WebSocketContext";
import { useEffect, useState, useCallback } from "react";
import ProtectedRoute from '@/components/ProtectedRoute';

// ✅ Add here
function normalizeThreatList(resp: any): ThreatResponse[] {
  if (Array.isArray(resp)) return resp as ThreatResponse[];
  if (Array.isArray(resp?.data)) return resp.data as ThreatResponse[];
  if (Array.isArray(resp?.data?.data)) return resp.data.data as ThreatResponse[];
  if (Array.isArray(resp?.items)) return resp.items as ThreatResponse[];
  if (Array.isArray(resp?.data?.items)) return resp.data.items as ThreatResponse[];
  return [];
}

export default function ThreatsPage() {
  const [threats, setThreats] = useState<ThreatResponse[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // WebSocket integration for live updates
  const { lastMessage } = useWebSocketContext();
  
  // Batch selection state
  const [selectedThreats, setSelectedThreats] = useState<Set<number>>(new Set());
  const [isSelectAll, setIsSelectAll] = useState(false);
  
  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  
  // 🆕 Copy to clipboard state
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  // 🆕 SHAP Explain modal
const [selectedThreat, setSelectedThreat] = useState<ThreatResponse | null>(null);
const [shapData, setShapData] = useState<any>(null);
const [shapLoading, setShapLoading] = useState(false);

  // Fetch threats with correlations
  const fetchThreats = useCallback(async () => {
    try {
      setIsLoading(true);

      const params: Record<string, string> = {};
      if (severityFilter !== "all") params.severity = severityFilter;
      if (statusFilter !== "all") params.status = statusFilter;

      const response = await threatsApi.getThreats(params);

      if (response.success && response.data) {
        const items = Array.isArray(response.data)
          ? response.data
          : normalizeThreatList(response.data);

        const threatsWithCorrelations = await Promise.all(
          items.map(async (threat) => {
            try {
              const correlationResponse = await httpFetch(
                `/api/threats/${threat.id}/correlations`
              );
              const correlationData = await correlationResponse.json();
              return {
                ...threat,
                correlation: correlationData.success ? correlationData.correlations : null,
              };
            } catch (err) {
              console.error(`Failed to fetch correlations for threat ${threat.id}:`, err);
              return {
                ...threat,
                correlation: null,
                created_at: threat.created_at ?? new Date().toISOString(),
                updated_at: threat.updated_at ?? new Date().toISOString(),
              };
            }
          })
        );

        setThreats(threatsWithCorrelations);
        setError(null);
      } else {
        console.warn("🟡 API returned no threats data:", response);
        setThreats([]);
        setError(null);
      }
    } catch (err) {
      console.error("Error fetching threats:", err);
      setThreats([]);
      setError("Failed to fetch threats");
    } finally {
      setIsLoading(false);
    }
  }, [severityFilter, statusFilter]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await threatsApi.getStats();
      if (response.success && response.data) {
        setStats(response.data as ThreatStats);
      } else {
        console.warn("🟡 Threat stats request did not succeed:", response);
        setStats(null);
      }
    } catch (err) {
      console.error("Error fetching stats:", err);
      setStats(null);
    }
  }, []);

  // Block threat
  const blockThreat = async (threatId: number) => {
    try {
      const response = await threatsApi.blockThreat(threatId);
      if (response.success) {
        await fetchThreats();
        await fetchStats();
      } else {
        alert(response.error || "Failed to block threat");
      }
    } catch (err) {
      console.error("Error blocking threat:", err);
      alert("Failed to block threat");
    }
  };

  // Dismiss threat
  const dismissThreat = async (threatId: number) => {
    try {
      const response = await threatsApi.dismissThreat(threatId);
      if (response.success) {
        await fetchThreats();
        await fetchStats();
      } else {
        alert(response.error || "Failed to dismiss threat");
      }
    } catch (err) {
      console.error("Error dismissing threat:", err);
      alert("Failed to dismiss threat");
    }
  };

  // Initial load
  useEffect(() => {
    fetchStats();
    fetchThreats();
  }, [fetchStats, fetchThreats, severityFilter, statusFilter]);

  // Listen for live threat updates via WebSocket
  useEffect(() => {
    if (!lastMessage) return;
    if (lastMessage.type === 'threat_update') {
      console.log('🚨 New threat received via WebSocket!', lastMessage.data);
      fetchThreats();
      fetchStats();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastMessage]);

  // Format timestamp
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  };

  // Toggle select all
  const toggleSelectAll = () => {
    if (isSelectAll) {
      setSelectedThreats(new Set());
      setIsSelectAll(false);
    } else {
      const allIds = new Set(threats.map(t => t.id));
      setSelectedThreats(allIds);
      setIsSelectAll(true);
    }
  };

  // Toggle single threat selection
  const toggleThreatSelection = (threatId: number) => {
    const newSelected = new Set(selectedThreats);
    if (newSelected.has(threatId)) {
      newSelected.delete(threatId);
    } else {
      newSelected.add(threatId);
    }
    setSelectedThreats(newSelected);
    setIsSelectAll(newSelected.size === threats.length);
  };

  // Batch block threats
  const batchBlockThreats = async () => {
    if (selectedThreats.size === 0) return;
    if (!confirm(`Block ${selectedThreats.size} threats?`)) return;
    try {
      const response = await threatsApi.batchAction({
        threat_ids: Array.from(selectedThreats),
        action: 'block',
        reason: 'Bulk block action'
      });
      if (response.success) {
        await fetchThreats();
        await fetchStats();
        setSelectedThreats(new Set());
        setIsSelectAll(false);
      } else {
        alert(response.error || 'Failed to block threats');
      }
    } catch (err) {
      console.error('Batch block failed:', err);
      alert('Failed to block threats');
    }
  };

  // Batch dismiss threats
  const batchDismissThreats = async () => {
    if (selectedThreats.size === 0) return;
    if (!confirm(`Dismiss ${selectedThreats.size} threats?`)) return;
    try {
      const response = await threatsApi.batchAction({
        threat_ids: Array.from(selectedThreats),
        action: 'dismiss',
        reason: 'Bulk dismiss action'
      });
      if (response.success) {
        await fetchThreats();
        await fetchStats();
        setSelectedThreats(new Set());
        setIsSelectAll(false);
      } else {
        alert(response.error || 'Failed to dismiss threats');
      }
    } catch (err) {
      console.error('Batch dismiss failed:', err);
      alert('Failed to dismiss threats');
    }
  };

  // Batch delete threats
  const batchDeleteThreats = async () => {
    if (selectedThreats.size === 0) return;
    if (!confirm(`Permanently delete ${selectedThreats.size} threats? This cannot be undone!`)) return;
    try {
      const response = await threatsApi.batchAction({
        threat_ids: Array.from(selectedThreats),
        action: 'delete',
        reason: 'Bulk delete action'
      });
      if (response.success) {
        await fetchThreats();
        await fetchStats();
        setSelectedThreats(new Set());
        setIsSelectAll(false);
      } else {
        alert(response.error || 'Failed to delete threats');
      }
    } catch (err) {
      console.error('Batch delete failed:', err);
      alert('Failed to delete threats');
    }
  };

  // 🆕 Copy IP to clipboard
  const copyIpToClipboard = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // 🆕 Open external URL via Tauri
 const openExternalUrl = async (e: React.MouseEvent, url: string) => {
  e.stopPropagation();
  try {
    const opener = await import('@tauri-apps/plugin-opener');
    await opener.openUrl(url);
  } catch {
    window.open(url, '_blank', 'noopener,noreferrer');
  }
};

// 🆕 Fetch SHAP explanation
const fetchShapData = async (threat: ThreatResponse) => {
  setSelectedThreat(threat);
  setShapData(null);
  setShapLoading(true);

  try {
    console.log('All localStorage keys:', Object.keys(localStorage));
  const authToken = localStorage.getItem('access_token') || 
                  sessionStorage.getItem('access_token') || '';

const response = await httpFetch('/api/ml/explain', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`
  },
  body: JSON.stringify({
    timestamp: threat.timestamp,
    source_ip: threat.source_ip,
    source_port: 80,
    payload: threat.description,
    request_type: 'HTTP',
    country: 'BG',
  }),
});
    const data = await response.json();
    if (data.success) {
      setShapData(data.explanation);
    } else {
      setShapData({ error: 'Explanation not available' });
    }
  } catch (err) {
    setShapData({ error: 'Failed to fetch explanation' });
  } finally {
    setShapLoading(false);
  }
};

  // Severity badge class
  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case "critical": return "badge badge--err";
      case "high": return "badge badge--warn";
      case "medium": return "badge badge--info";
      case "low": return "badge badge--ok";
      default: return "badge";
    }
  };

  // Status badge class
  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case "active": return "badge badge--err";
      case "blocked": return "badge badge--ok";
      case "dismissed": return "badge";
      default: return "badge";
    }
  };

  // 🆕 Get row hover gradient based on severity
  const getRowHoverGradient = (severity: string) => {
    switch (severity) {
      case "critical": 
        return "hover:bg-gradient-to-r hover:from-red-500/10 hover:via-red-500/5 hover:to-transparent";
      case "high": 
        return "hover:bg-gradient-to-r hover:from-orange-500/10 hover:via-orange-500/5 hover:to-transparent";
      case "medium": 
        return "hover:bg-gradient-to-r hover:from-yellow-500/10 hover:via-yellow-500/5 hover:to-transparent";
      case "low": 
        return "hover:bg-gradient-to-r hover:from-blue-500/10 hover:via-blue-500/5 hover:to-transparent";
      default: 
        return "hover:bg-gradient-to-r hover:from-purple-500/10 hover:via-purple-500/5 hover:to-transparent";
    }
  };

  // 🆕 LOLBins count for stats card
  const lolbinsCount = threats.filter(t => t.threat_type === 'lolbins_abuse').length;

  return (
    <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Threat Management
            </h1>
            <p className="mt-2 text-muted-foreground text-sm">
  Monitor and respond to security threats in real-time
</p>
<p className="mt-1 text-xs text-muted-foreground/70">
  Detects{" "}
  <span className="text-orange-400 font-medium">LOLBins Abuse</span>,{" "}
  <span className="text-red-400 font-medium">WMI Abuse</span>,{" "}
  <span className="text-blue-400 font-medium">PowerShell Attacks</span>,{" "}
  <span className="text-purple-400 font-medium">Process Injection</span> and more
</p>
          </div>
          
          <button
            onClick={() => {
              fetchThreats();
              fetchStats();
            }}
            className="btn btn-primary"
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="section">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="h-5 w-5 text-blue-500" />
                <div className="text-sm text-muted-foreground">Total Threats</div>
              </div>
              <div className="text-2xl font-bold">
                {stats.total_threats}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/30">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-500" />
                <div className="text-sm text-muted-foreground">Critical</div>
              </div>
              <div className="text-2xl font-bold text-red-500">
                {stats.severity_breakdown.critical || 0}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-yellow-500/30">
              <div className="flex items-center gap-3 mb-2">
                <TrendingUp className="h-5 w-5 text-yellow-500" />
                <div className="text-sm text-muted-foreground">Active</div>
              </div>
              <div className="text-2xl font-bold text-yellow-500">
                {stats.status_breakdown.active || 0}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="h-5 w-5 text-green-500" />
                <div className="text-sm text-muted-foreground">Blocked</div>
              </div>
              <div className="text-2xl font-bold text-green-500">
                {stats.status_breakdown.blocked || 0}
              </div>
            </div>

            {/* 🆕 LOLBins Stats Card */}
            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-orange-500/30 border border-orange-500/20">
              <div className="flex items-center gap-3 mb-2">
                <span className="text-lg">⚠️</span>
                <div className="text-sm text-muted-foreground">LOLBins</div>
              </div>
              <div className="text-2xl font-bold text-orange-400">
                {lolbinsCount}
              </div>
              <div className="text-xs text-orange-400/60 mt-1 font-mono">T1218</div>
            </div>
          </div>
        </div>
      )}

      {/* ML Threat Analysis Panel */}
<div className="w-full bg-gray-800/40 border border-gray-700/50 rounded-xl p-5 mb-4">
  <div className="flex items-center gap-2 mb-4">
    <div className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
    <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
      ML Threat Analysis
    </span>
    {selectedThreat && (
      <span className="ml-auto text-xs text-gray-400">
        {selectedThreat.threat_type} — {selectedThreat.source_ip}
      </span>
    )}
  </div>

  {!selectedThreat && (
    <div className="flex items-center gap-8">
      <div className="flex-1">
        <div className="mb-3 flex items-center justify-between">
          <span className="text-xs text-gray-400">ML Prediction</span>
          <span className="text-xs font-bold px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30">
            SYSTEM CLEAN
          </span>
        </div>
        <p className="text-xs text-gray-500 mb-3">
          Click any threat row to see live SHAP analysis
        </p>
        {!selectedThreat && (
  <button
    onClick={() => fetchShapData({
      id: 1,
      threat_type: 'lolbins_abuse',
      severity: 'high',
      source_ip: 'PID:1234',
      description: 'Test LOLBin abuse detected',
      confidence_score: 87.5,
      timestamp: new Date().toISOString(),
      status: 'active'
    } as ThreatResponse)}
    className="mt-3 text-xs px-3 py-1 bg-cyan-500/20 border border-cyan-500/30 rounded text-cyan-400 hover:bg-cyan-500/30 transition-colors"
  >
    🧪 Test SHAP Analysis
  </button>
)}
        {[
          { label: 'payload_entropy', value: 85, color: 'bg-red-500',     sign: '+0.42' },
          { label: 'has_base64',      value: 65, color: 'bg-red-400',     sign: '+0.31' },
          { label: 'has_cmd',         value: 50, color: 'bg-orange-400',  sign: '+0.28' },
          { label: 'payload_len',     value: 35, color: 'bg-yellow-500',  sign: '+0.19' },
          { label: 'geo_risk',        value: 15, color: 'bg-green-500',   sign: '-0.08' },
        ].map((item, idx) => (
          <div key={idx} className="mb-2 opacity-40">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-mono text-gray-400">{item.label}</span>
              <span className="text-xs font-bold text-gray-500">{item.sign}</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-1.5">
              <div className={`h-1.5 rounded-full ${item.color}`} style={{ width: `${item.value}%` }} />
            </div>
          </div>
        ))}
      </div>
      <div className="text-center opacity-30">
        <Shield className="h-16 w-16 text-green-400 mx-auto" />
        <p className="text-xs text-green-400 mt-2">Protected</p>
      </div>
    </div>
  )}

  {selectedThreat && shapLoading && (
    <div className="text-center py-4">
      <RefreshCw className="h-6 w-6 animate-spin mx-auto text-cyan-400" />
      <p className="text-xs text-gray-400 mt-2">Analyzing with SHAP...</p>
    </div>
  )}

  {selectedThreat && shapData && !shapData.error && (
    <div className="flex items-start gap-8">
      <div className="flex-1">
        <div className="mb-3 flex items-center justify-between">
          <span className="text-xs text-gray-400">ML Prediction</span>
          <span className={`text-xs font-bold px-2 py-0.5 rounded ${
            shapData.prediction === 'malicious'
              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
              : 'bg-green-500/20 text-green-400 border border-green-500/30'
          }`}>
            {shapData.prediction?.toUpperCase()}
          </span>
        </div>
        {shapData.top_features?.map((feat: any, idx: number) => (
          <div key={idx} className="mb-2">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-mono text-gray-300">{feat.feature}</span>
              <span className={`text-xs font-bold ${
                feat.impact === 'increases_risk' ? 'text-red-400' : 'text-green-400'
              }`}>
                {feat.impact === 'increases_risk' ? '+' : ''}{feat.shap_value}
              </span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full transition-all duration-500 ${
                  feat.impact === 'increases_risk' ? 'bg-red-500' : 'bg-green-500'
                }`}
                style={{ width: `${Math.min(feat.magnitude * 300, 100)}%` }}
              />
            </div>
          </div>
        ))}
        {shapData.explanation && (
          <div className="mt-3 p-2 bg-cyan-500/10 border border-cyan-500/20 rounded text-xs text-cyan-300">
            💡 {shapData.explanation}
          </div>
        )}
      </div>
      <div className="text-center">
        <div className={`text-3xl font-bold ${
          shapData.prediction === 'malicious' ? 'text-red-400' : 'text-green-400'
        }`}>
          {selectedThreat.severity?.toUpperCase()}
        </div>
        <div className="text-xs text-gray-400 mt-1">Severity</div>
        <div className="text-2xl font-bold text-cyan-400 mt-3">
          {(selectedThreat.confidence_score || 0).toFixed(1)}%
        </div>
        <div className="text-xs text-gray-400 mt-1">Confidence</div>
      </div>
    </div>
  )}
</div>

      {/* Filters & Table */}
      <div className="section">
        <div className="card-premium p-6">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-4 mb-6">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Filters:</span>
            </div>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground ml-auto transition-all duration-300 hover:border-purple-400 hover:bg-purple-500/5 focus:outline-none focus:ring-2 focus:ring-purple-500 cursor-pointer relative z-50"
              style={{ pointerEvents: 'auto', colorScheme: 'dark' }}
            >
              <option value="all" className="bg-[#0a0e27] text-white">All Severities</option>
              <option value="critical" className="bg-[#0a0e27] text-white">Critical</option>
              <option value="high" className="bg-[#0a0e27] text-white">High</option>
              <option value="medium" className="bg-[#0a0e27] text-white">Medium</option>
              <option value="low" className="bg-[#0a0e27] text-white">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all duration-300 hover:border-cyan-400 hover:bg-cyan-500/5 focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer relative z-50"
              style={{ pointerEvents: 'auto', colorScheme: 'dark' }}
            >
              <option value="all" className="bg-[#0a0e27] text-white">All Statuses</option>
              <option value="active" className="bg-[#0a0e27] text-white">Active</option>
              <option value="blocked" className="bg-[#0a0e27] text-white">Blocked</option>
              <option value="dismissed" className="bg-[#0a0e27] text-white">Dismissed</option>
            </select>

            <div className="ml-auto text-sm text-muted-foreground">
              {threats?.length || 0} threats
            </div>
          </div>

          {/* Batch Actions */}
          {selectedThreats.size > 0 && (
            <div className="mb-4 p-4 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-lg animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-500/20">
                    <span className="text-sm font-bold text-purple-400">{selectedThreats.size}</span>
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-foreground">
                      {selectedThreats.size} threat{selectedThreats.size > 1 ? 's' : ''} selected
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Choose an action to apply to selected threats
                    </div>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={batchBlockThreats}
                    className="px-4 py-2 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/50 flex items-center gap-2 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <Ban className="h-4 w-4" />
                    Block All
                  </button>
                  <button
                    onClick={batchDismissThreats}
                    className="px-4 py-2 rounded-lg bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 border border-yellow-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-yellow-500/50 flex items-center gap-2 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <X className="h-4 w-4" />
                    Dismiss All
                  </button>
                  <button
                    onClick={batchDeleteThreats}
                    className="px-4 py-2 rounded-lg bg-gray-500/20 text-gray-400 hover:bg-gray-500/30 border border-gray-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-gray-500/50 flex items-center gap-2 relative z-50"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <X className="h-4 w-4" />
                    Delete All
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Loading / Error */}
          {isLoading && (
            <div className="text-center py-12">
              <RefreshCw className="h-8 w-8 animate-spin mx-auto text-primary" />
              <p className="mt-4 text-muted-foreground">Loading threats...</p>
            </div>
          )}

          {error && (
            <div className="text-center py-12">
              <AlertTriangle className="h-8 w-8 mx-auto text-red-500" />
              <p className="mt-4 text-red-500">{error}</p>
            </div>
          )}

          {/* Table */}
          {!isLoading && (
            <div className="overflow-x-auto">
              <table className="table w-full min-w-[900px]">
                <thead>
                  <tr>
                    <th className="px-2">
                      <div className="flex items-center justify-center">
                        <input
                          type="checkbox"
                          checked={isSelectAll}
                          onChange={toggleSelectAll}
                          className="w-5 h-5 rounded border-gray-600 bg-gray-700 text-primary focus:ring-primary focus:ring-offset-gray-900 cursor-pointer relative z-[60] transition-all duration-300 hover:scale-110"
                          style={{ pointerEvents: 'auto' }}
                        />
                      </div>
                    </th>
                    <th className="px-2">Time</th>
                    <th className="px-2">Source IP</th>
                    <th className="px-2">Type</th>
                    <th className="px-3">Description</th>
                    <th className="px-2">Severity</th>
                    <th className="px-2">Confidence</th>
                    <th className="px-2">IOC Match</th>
                    <th className="px-2">Status</th>
                    <th className="px-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {threats?.length === 0 ? (
                    <tr>
                  <td colSpan={10} className="text-center py-16">
  <div className="flex flex-col items-center gap-3">
    <Shield className="h-12 w-12 text-green-500/40" />
    <p className="text-green-400 font-semibold">System Protected</p>
    <p className="text-xs text-muted-foreground">
      No threats detected — monitoring active
    </p>
  </div>
</td>
                    </tr>
                  ) : (
                    threats?.map((threat) => (
                      <tr
  key={threat.id}
  onClick={() => fetchShapData(threat)}
  style={{ cursor: 'pointer' }}
  className={`
    group
    transition-all duration-300
                          ${getRowHoverGradient(threat.severity)}
                          hover:shadow-lg
                          ${threat.severity === 'critical' ? 'hover:shadow-red-500/20' : ''}
                          ${threat.severity === 'high' ? 'hover:shadow-orange-500/20' : ''}
                          ${threat.severity === 'medium' ? 'hover:shadow-yellow-500/20' : ''}
                          ${threat.severity === 'low' ? 'hover:shadow-blue-500/20' : ''}
                        `}
                      >
                        {/* Checkbox */}
                        <td className="px-2" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-center relative z-[60]">
                            <input
                              type="checkbox"
                              checked={selectedThreats.has(threat.id)}
                              onChange={() => toggleThreatSelection(threat.id)}
                              onClick={(e) => e.stopPropagation()}
                              className="w-5 h-5 rounded border-gray-600 bg-gray-700 text-primary focus:ring-primary focus:ring-offset-gray-900 cursor-pointer transition-all duration-300 hover:scale-110"
                              style={{ pointerEvents: 'auto' }}
                            />
                          </div>
                        </td>

                        {/* Time */}
                        <td className="px-2 font-mono text-xs transition-colors duration-300 group-hover:text-blue-400">
                          {formatTime(threat.timestamp)}
                        </td>

                        {/* Source IP */}
                        <td className="px-2 font-mono text-xs">
                          <div className="flex items-center gap-1">
                            <span className="text-blue-400 transition-all duration-300 group-hover:text-blue-300 group-hover:drop-shadow-[0_0_8px_rgba(59,130,246,0.5)] truncate">
                              {threat.source_ip}
                            </span>
                            <button
                              onClick={() => copyIpToClipboard(threat.source_ip)}
                              className="opacity-0 group-hover:opacity-100 transition-all duration-300 hover:scale-110 text-gray-400 hover:text-blue-400 relative z-50 flex-shrink-0"
                              style={{ pointerEvents: 'auto' }}
                              title="Copy IP"
                            >
                              {copiedIp === threat.source_ip ? (
                                <CheckCircle2 className="h-3 w-3 text-green-400" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </div>
                        </td>

                        {/* Type - Enhanced badges */}
<td className="px-2">
  {threat.threat_type === 'lolbins_abuse' ? (
    <div className="flex flex-col gap-1">
      <span className="px-2 py-0.5 bg-orange-500/20 border border-orange-500/30 rounded text-xs text-orange-400 font-medium whitespace-nowrap transition-all duration-300 group-hover:bg-orange-500/30 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-orange-500/50">
        ⚠️ LOLBins Abuse
      </span>
      <button
        onClick={(e) => openExternalUrl(e, 'https://attack.mitre.org/techniques/T1218/')}
        className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline transition-colors duration-200 font-mono text-left"
      >
        MITRE T1218 ↗
      </button>
    </div>
  ) : threat.threat_type === 'wmi_abuse' ? (
    <div className="flex flex-col gap-1">
      <span className="px-2 py-0.5 bg-red-500/20 border border-red-500/30 rounded text-xs text-red-400 font-medium whitespace-nowrap transition-all duration-300 group-hover:bg-red-500/30 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-red-500/50">
        🔴 WMI Abuse
      </span>
      <button
        onClick={(e) => openExternalUrl(e, 'https://attack.mitre.org/techniques/T1047/')}
        className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline transition-colors duration-200 font-mono text-left"
      >
        MITRE T1047 ↗
      </button>
    </div>
  ) : threat.threat_type === 'powershell_abuse' ? (
    <div className="flex flex-col gap-1">
      <span className="px-2 py-0.5 bg-blue-500/20 border border-blue-500/30 rounded text-xs text-blue-400 font-medium whitespace-nowrap transition-all duration-300 group-hover:bg-blue-500/30 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-blue-500/50">
        💙 PowerShell Abuse
      </span>
      <button
        onClick={(e) => openExternalUrl(e, 'https://attack.mitre.org/techniques/T1059/001/')}
        className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline transition-colors duration-200 font-mono text-left"
      >
        MITRE T1059.001 ↗
      </button>
    </div>
  ) : (
    <span className="font-semibold text-sm transition-colors duration-300 group-hover:text-purple-400 truncate">
      {threat.threat_type}
    </span>
  )}
</td>

                        {/* Description */}
                        <td className="px-3 text-sm" title={threat.description}>
                          <div className="truncate transition-colors duration-300 group-hover:text-foreground">
                            {threat.description}
                          </div>
                        </td>

                        {/* Severity */}
                        <td className="px-2">
                          <span className={`
                            ${getSeverityBadgeClass(threat.severity)}
                            transition-all duration-300
                            group-hover:scale-110
                            ${threat.severity === 'critical' ? 'group-hover:shadow-lg group-hover:shadow-red-500/50' : ''}
                            ${threat.severity === 'high' ? 'group-hover:shadow-lg group-hover:shadow-orange-500/50' : ''}
                            relative inline-block whitespace-nowrap
                          `}>
                            {threat.severity === 'critical' && (
                              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                              </span>
                            )}
                            {threat.severity}
                          </span>
                        </td>

                        {/* Confidence Score */}
                        <td className="px-2">
                          <div className="flex items-center gap-2">
                            <div className="w-14 bg-gray-700 rounded-full h-2 overflow-hidden relative group-hover:shadow-md flex-shrink-0">
                              <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
                              </div>
                              <div
                                className={`
                                  h-2 rounded-full transition-all duration-500
                                  ${(threat.confidence_score || 0) >= 80 ? 'bg-green-500 group-hover:shadow-green-500/50' :
                                    (threat.confidence_score || 0) >= 60 ? 'bg-yellow-500 group-hover:shadow-yellow-500/50' :
                                    'bg-red-500 group-hover:shadow-red-500/50'}
                                `}
                                style={{
                                  width: `${threat.confidence_score || 0}%`,
                                  animation: 'fillBar 1s ease-out'
                                }}
                              />
                            </div>
                            <span className="text-xs font-mono transition-all duration-300 group-hover:text-foreground group-hover:font-semibold whitespace-nowrap">
                              {(threat.confidence_score || 0).toFixed(1)}%
                            </span>
                          </div>
                        </td>

                        {/* IOC Match */}
                        <td className="px-2">
                          {threat.correlation && threat.correlation.match_count > 0 ? (
                            <div className="flex flex-col gap-1">
                              <div className="flex items-center gap-1">
                                <span className="px-2 py-0.5 bg-purple-500/20 border border-purple-500/30 rounded text-xs text-purple-400 font-medium transition-all duration-300 group-hover:bg-purple-500/30 group-hover:scale-105 group-hover:shadow-lg group-hover:shadow-purple-500/50 whitespace-nowrap">
                                  🔗 {threat.correlation.match_count} IOC{threat.correlation.match_count > 1 ? 's' : ''}
                                </span>
                              </div>
                              <div className="flex items-center gap-1">
                                <span className="text-xs text-gray-400 transition-colors duration-300 group-hover:text-purple-300 whitespace-nowrap">
                                  {threat.correlation.correlation_score}% conf
                                </span>
                              </div>
                            </div>
                          ) : (
                            <span className="text-xs text-gray-500 transition-colors duration-300 group-hover:text-gray-400 whitespace-nowrap">
                              No match
                            </span>
                          )}
                        </td>

                        {/* Status */}
                        <td className="px-2">
                          <span className={`
                            ${getStatusBadgeClass(threat.status)}
                            transition-all duration-300
                            group-hover:scale-110
                            ${threat.status === 'active' ? 'group-hover:shadow-lg group-hover:shadow-red-500/50' : ''}
                            ${threat.status === 'blocked' ? 'group-hover:shadow-lg group-hover:shadow-green-500/50' : ''}
                            relative inline-block whitespace-nowrap
                          `}>
                            {threat.status === 'active' && (
                              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-yellow-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500"></span>
                              </span>
                            )}
                            {threat.status}
                          </span>
                        </td>

                        {/* Actions */}
                        <td className="px-2">
                          <div className="flex gap-1.5">
                            {threat.status === "active" && (
                              <>
                                <button
                                  onClick={() => blockThreat(threat.id)}
                                  className="btn btn-ghost text-red-500 hover:bg-red-500/10 transition-all duration-300 hover:scale-110 hover:shadow-lg hover:shadow-red-500/50 relative z-50 p-1.5"
                                  style={{ pointerEvents: 'auto' }}
                                  title="Block Threat"
                                >
                                  <Ban className="h-4 w-4 transition-transform duration-300 hover:rotate-12" />
                                </button>
                                <button
                                  onClick={() => dismissThreat(threat.id)}
                                  className="btn btn-ghost hover:bg-muted transition-all duration-300 hover:scale-110 hover:shadow-lg hover:shadow-gray-500/50 relative z-50 p-1.5"
                                  style={{ pointerEvents: 'auto' }}
                                  title="Dismiss Threat"
                                >
                                  <X className="h-4 w-4 transition-transform duration-300 hover:rotate-90" />
                                </button>
                              </>
                            )}
                            {threat.status !== "active" && (
                              <span className="text-xs text-muted-foreground transition-colors duration-300 group-hover:text-foreground whitespace-nowrap">
                                {threat.status}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
      {/* 🆕 SHAP Confidence Breakdown Modal */}
{selectedThreat && (
  <div
    className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
    onClick={() => { setSelectedThreat(null); setShapData(null); }}
  >
    <div
      className="bg-gray-900 border border-gray-700 rounded-xl p-6 max-w-lg w-full shadow-2xl"
      onClick={(e) => e.stopPropagation()}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg font-bold text-white">🔍 Threat Analysis</h3>
          <p className="text-sm text-gray-400 mt-1">
            {selectedThreat.threat_type} — {selectedThreat.source_ip}
          </p>
        </div>
        <button
          onClick={() => { setSelectedThreat(null); setShapData(null); }}
          className="text-gray-400 hover:text-white transition-colors text-xl"
        >
          ×
        </button>
      </div>

      {/* Threat Info */}
      <div className="mb-4 p-3 bg-gray-800 rounded-lg">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-400">Severity</span>
          <span className={`text-xs font-bold ${
            selectedThreat.severity === 'critical' ? 'text-red-400' :
            selectedThreat.severity === 'high' ? 'text-orange-400' :
            selectedThreat.severity === 'medium' ? 'text-yellow-400' :
            'text-blue-400'
          }`}>{selectedThreat.severity.toUpperCase()}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-gray-400">Confidence</span>
          <span className="text-xs font-bold text-green-400">
            {(selectedThreat.confidence_score || 0).toFixed(1)}%
          </span>
        </div>
        <p className="text-xs text-gray-300 mt-2">{selectedThreat.description}</p>
      </div>

      {/* SHAP Section */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">
          🧠 ML Confidence Breakdown
        </h4>

        {shapLoading && (
          <div className="text-center py-6">
            <RefreshCw className="h-6 w-6 animate-spin mx-auto text-cyan-400" />
            <p className="text-xs text-gray-400 mt-2">Analyzing with SHAP...</p>
          </div>
        )}

        {shapData?.error && (
          <div className="text-center py-4 text-gray-500 text-sm">
            {shapData.error}
          </div>
        )}

        {shapData && !shapData.error && (
          <>
            {/* Prediction */}
            <div className="mb-3 flex items-center justify-between">
              <span className="text-xs text-gray-400">ML Prediction</span>
              <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                shapData.prediction === 'malicious'
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'bg-green-500/20 text-green-400 border border-green-500/30'
              }`}>
                {shapData.prediction?.toUpperCase()}
              </span>
            </div>

            {/* Top Features */}
            <div className="space-y-2">
              {shapData.top_features?.map((feat: any, idx: number) => (
                <div key={idx}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-gray-300">
                      {feat.feature}
                    </span>
                    <span className={`text-xs font-bold ${
                      feat.impact === 'increases_risk' ? 'text-red-400' : 'text-green-400'
                    }`}>
                      {feat.impact === 'increases_risk' ? '+' : ''}{feat.shap_value}
                    </span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full transition-all duration-500 ${
                        feat.impact === 'increases_risk' ? 'bg-red-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${Math.min(feat.magnitude * 300, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* Explanation */}
            {shapData.explanation && (
              <div className="mt-4 p-2 bg-cyan-500/10 border border-cyan-500/20 rounded text-xs text-cyan-300">
                💡 {shapData.explanation}
              </div>
            )}

            {/* Method */}
            <div className="mt-2 text-right">
              <span className="text-xs text-gray-500 font-mono">
                via {shapData.method}
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  </div>
)}
    </main>
    </ProtectedRoute>
  );
}